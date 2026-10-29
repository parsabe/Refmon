"""Phase 7: variant and robustness testing (CLAUDE.md Phase 7).

Done when: the matrix is generated in CI and every allowed variant is either fixed or documented as a
known gap. The structural rules and weights are frozen, so an allowed variant is documented in
tests/variants/known_gaps.yaml and linked to a design finding in docs/progress.md; the xfail test of
tests/test_v13.py says what a robust pipeline would do, and turns into a failure (XPASS) the day it
is fixed."""

import csv
import itertools
import re
from collections import Counter

import pytest

from refmon import variants as v
from refmon.golden import ScenarioKind, load_golden_cases
from refmon.policy import default_policy
from refmon.replay import ReplaySource
from refmon.schemas import Decision, EventType
from scenario_run import GOLDEN_DIR, ROOT

GAPS_FILE = ROOT / "tests" / "variants" / "known_gaps.yaml"
POLICY = default_policy()
CASES = load_golden_cases(GOLDEN_DIR)
MALICIOUS = [c for c in CASES if c.expected.kind is ScenarioKind.MALICIOUS]


@pytest.fixture(scope="module")
def generated():
    return v.generate(CASES, POLICY)


@pytest.fixture(scope="module")
def results(generated):
    return v.run_all(generated, POLICY)


# -- the seed (CLAUDE.md C11, weight methodology) --------------------------------------------------------


def test_the_seed_is_recorded_and_not_retired():
    text = (ROOT / "docs" / "variant-seeds.md").read_text()
    row = re.search(rf"\|\s*{v.SEED}\s*\|[^|]*\|\s*\*\*(\w+)\*\*", text)
    assert row and row.group(1) == "active"
    retired = text.split("## Retired seeds")[1]
    assert str(v.SEED) not in retired


def test_the_weights_are_still_those_of_the_specification():
    """The seed is valid only while the weights are the frozen ones of CLAUDE.md C11."""
    text = (ROOT / "CLAUDE.md").read_text()
    block = text[text.index("  weights:") : text.index("  surprisal_max_bits")]
    spec = {k: float(x) for k, x in re.findall(r"^\s{4}([a-z_]+): ([0-9.]+)", block, flags=re.M)}
    assert spec and spec == POLICY.math.weights  # a change retires the seed (docs/variant-seeds.md)


# -- generation ---------------------------------------------------------------------------------------------


def test_every_malicious_golden_file_gets_a_baseline_and_variants(generated):
    by = Counter(x.scenario for x in generated if x.kind == "malicious")
    assert set(by) == {c.scenario for c in MALICIOUS}
    assert all(n >= 3 for n in by.values()), by  # S14, S17 and S27 have only a few events
    assert sum(by.values()) > 500


def test_generation_is_deterministic_for_a_seed():
    first = [(x.scenario, x.name, x.dims, len(x.events)) for x in v.generate(CASES, POLICY)]
    second = [(x.scenario, x.name, x.dims, len(x.events)) for x in v.generate(CASES, POLICY)]
    other = [(x.scenario, x.name, x.dims, len(x.events)) for x in v.generate(CASES, POLICY, seed=1)]
    assert first == second and first != other


def test_every_dimension_of_the_specification_is_varied(generated):
    levels = {(d, lvl) for x in generated for d, lvl in x.dims.items()}
    for dim, wanted in v.DIMENSIONS.items():
        assert {(dim, w) for w in wanted} <= levels, dim
    assert set(v.DIMENSIONS) == {
        "delivery", "entry", "obfuscation", "timing", "destination", "lineage"
    }  # fmt: skip


def test_every_variant_is_a_valid_replay_stream(generated):
    for x in generated:
        previous = None
        ids = set()
        for e in x.events:
            assert e.event_id not in ids
            ids.add(e.event_id)
            assert previous is None or e.ts >= previous
            previous = e.ts
            type(e).from_json_line(e.to_json_line(), extra_roles=tuple(POLICY.extra_roles))


def test_the_mutations_do_what_they_say():
    events = list(ReplaySource(GOLDEN_DIR / "S01.events.jsonl", extra_roles=POLICY.extra_roles))
    typed = v.delivery(events, "typed")
    pasted_fp = next(e for e in events if e.type is EventType.USER_INPUT).object.fingerprint
    assert all(
        e.object.fingerprint != pasted_fp
        for e in typed
        if e.type in (EventType.EXEC, EventType.USER_INPUT)
    )
    assert {e.attrs.get("input_method") for e in typed if e.type is EventType.USER_INPUT} == {
        "typed"
    }
    stripped = v.obfuscation(events, "stripped")
    assert not any("hidden_window" in e.attrs or "encoded_payload" in e.attrs for e in stripped)
    deep = v.lineage(events, "3")
    assert len(deep) == len(events) + 3 * len({e.actor.id for e in events if e.actor.parent})
    slow = v.timing(events, "beyond_window", 600.0)
    assert min((b.ts - a.ts).total_seconds() for a, b in itertools.pairwise(slow)) >= 660
    assert v.entry(events, "scheduled_task")[2].actor.role in {"scheduler", "browser"}


def test_a_mutation_that_does_not_apply_returns_nothing():
    server = list(ReplaySource(GOLDEN_DIR / "S15.events.jsonl", extra_roles=POLICY.extra_roles))
    assert v.delivery(server, "typed") is None  # no user input to type
    shell = list(ReplaySource(GOLDEN_DIR / "S13.events.jsonl", extra_roles=POLICY.extra_roles))
    assert v.entry(shell, "terminal") is not None
    assert v.entry(server, "terminal") is None  # no process starts anything in S15
    assert v.lineage(server[:1], "2") is None  # no child process


# -- the results ----------------------------------------------------------------------------------------------


def test_the_unmodified_files_reach_their_golden_decisions(results):
    for r in results:
        if r.variant.name == "baseline":
            assert r.decision is r.variant.expected, r.variant.scenario


def test_the_no_label_variants_of_s17_to_s20_are_blocked(results):
    """D22: the Contract signals do not depend on the origin label."""
    no_label = [r for r in results if r.variant.name == "no-label"]
    assert sorted(r.variant.scenario for r in no_label) == ["S17", "S18", "S19", "S20"]
    for r in no_label:
        assert "origin" not in r.failed, r.variant.scenario
        assert r.decision is Decision.BLOCK, r.variant.scenario


def test_the_matrix_has_a_row_per_variant_and_the_columns_of_the_specification(results, tmp_path):
    path = tmp_path / "matrix.csv"
    v.write_csv(results, path)
    rows = list(csv.DictReader(path.open()))
    assert len(rows) == len(results)
    assert list(rows[0]) == v.CSV_COLUMNS
    assert {"scenario", "variant", "decision", "role_other_share"} <= set(rows[0])
    assert {r["decision"] for r in rows} <= {"allow", "hold", "block"}


def test_the_share_of_role_other_is_reported(results):
    shares = [r.other_share for r in results]
    assert all(0.0 <= s <= 1.0 for s in shares)
    assert "role 'other'" in v.summarize(results)
    # a high share would mean the contracts do not cover the workload: report it, per run
    assert max(shares) > 0 and sum(shares) / len(shares) < 0.5


def test_holds_record_what_a_person_can_do_about_them(results):
    held = [r for r in v.malicious(results) if r.decision is Decision.HOLD]
    assert held
    # A hold of a variant whose events are further apart than the endpoint hold timeout (a timing
    # mutation, or S06 whose payload runs a day later) can time out while the replay goes on, and
    # then has no open question left to answer (the Q7 limitation in docs/progress.md). Every other
    # hold records what each answer does.
    wait = POLICY.decisions.endpoint_hold_timeout

    def spread(r):
        times = [e.ts for e in r.variant.events]
        return any((b - a).total_seconds() > wait for a, b in itertools.pairwise(times))

    unspread = [r for r in held if not spread(r)]
    assert unspread and all(r.holds for r in unspread)
    outcomes = {o for r in held for o in r.holds.values()}
    assert "released: the attack proceeds" in outcomes  # continuing or releasing lets it through
    assert "contained" in outcomes
    assert any("stays paused and quarantined" in o for o in outcomes)


def test_the_matrix_splits_holds_into_those_that_pause_something_and_those_that_do_not(
    results, tmp_path
):
    """F1: report block, effective hold and uncontained (allow plus a hold that pauses nothing)."""
    split = v.split(results)
    assert split["block"] + split["effective_hold"] + split["uncontained"] == len(
        v.malicious(results)
    )
    assert split["uncontained"] == split["allow"] + split["hold_pauses_nothing"]
    assert "effective hold" in v.summarize(results) and "uncontained" in v.summarize(results)
    path = tmp_path / "m.csv"
    v.write_csv(results, path)
    rows = [r for r in csv.DictReader(path.open()) if r["kind"] == "malicious"]
    assert {r["outcome"] for r in rows} <= {
        "block", "effective_hold", "hold_pauses_nothing", "allow"
    }  # fmt: skip
    held = [r for r in rows if r["decision"] == "hold"]
    assert all((r["pauses"] == "1") == (r["outcome"] == "effective_hold") for r in held)


def test_a_hold_pauses_nothing_only_when_every_process_behind_it_is_a_channel_role(results):
    """v1.1 (A47) pauses the processes that produced a hold's signals; v1.2 (A51) keeps the channel
    roles (browser, mail, launcher) out of it, so a hold whose only producers are channel roles is
    the one kind that still pauses nothing."""
    from refmon.contain import signal_processes
    from refmon.pipeline import Pipeline

    channel = set(POLICY.non_carrier_roles)
    nothing = [r for r in v.malicious(results) if r.outcome == "hold_pauses_nothing"]
    for r in nothing:
        pipe = Pipeline(POLICY)
        for event in r.variant.events:
            pipe.process(event)
        best = pipe.best()
        rec = pipe.linker.records[best.story_id]
        role_of = {e.actor.id: e.actor.role for e in r.variant.events}
        behind = {role_of[p] for p in signal_processes(rec, best.signals)}
        assert behind <= channel, (r.variant.scenario, r.variant.name, behind)
    assert len(nothing) < 0.05 * len(results)


def test_no_block_of_the_matrix_acts_on_nothing(results):
    """v1.2 (A52): a block with no labeled process and no origin label acts on its producers."""
    assert [(r.variant.scenario, r.variant.name) for r in v.blocks_acting_on_nothing(results)] == []


# -- Done when: every allowed variant is documented ---------------------------------------------------------------


def test_every_allowed_malicious_variant_is_documented_as_a_known_gap(results):
    gaps = v.load_known_gaps(GAPS_FILE)
    missing = v.undocumented(results, gaps)
    assert [f"{r.variant.scenario} {r.variant.name}" for r in missing] == []


def test_no_documented_gap_is_stale(results):
    assert [g.id for g in v.stale(results, v.load_known_gaps(GAPS_FILE))] == []


def test_every_known_gap_names_a_finding_that_the_progress_log_records():
    progress = (ROOT / "docs" / "progress.md").read_text()
    for gap in v.load_known_gaps(GAPS_FILE):
        assert gap.finding and re.search(rf"\b{gap.finding}\b", progress), gap.id


def test_the_command_line_writes_the_matrix_and_the_allowed_list(tmp_path, capsys):
    out, allowed = tmp_path / "m.csv", tmp_path / "a.csv"
    code = v.main(["--golden", str(GOLDEN_DIR), "--known-gaps", str(GAPS_FILE),
                   "--out", str(out), "--allowed-out", str(allowed)])  # fmt: skip
    assert code == 0 and out.exists()
    assert allowed.read_text().startswith("scenario,variant,questions_failed,questions_passed")
    assert "variants" in capsys.readouterr().out


def test_the_command_line_fails_on_an_undocumented_allowed_variant(tmp_path):
    empty = tmp_path / "none.yaml"
    empty.write_text("gaps: []\n")
    code = v.main(["--golden", str(GOLDEN_DIR), "--known-gaps", str(empty),
                   "--out", str(tmp_path / "m.csv"), "--allowed-out", str(tmp_path / "a.csv")])  # fmt: skip
    assert code == 1


# -- expected failures: what a robust pipeline would do (linked to the findings) -------------------------------


def one(results, scenario, name):
    return next(r for r in results if r.variant.scenario == scenario and r.variant.name == name)


def test_a_payload_on_a_trusted_host_is_not_allowed(results):
    """F2, closed by v1.1 (A48): a labeled process gets `fetch` on a class its role does not list."""
    assert one(results, "S07", "destination=popular_trusted").decision is not Decision.ALLOW


# The expected failure of F3 (a slow burst) and the slow-leak test are pinned to fixed gaps in
# tests/test_v13.py: with the seed drawing the gaps, a variant named `timing=minutes` is no longer
# the same events for every seed.
