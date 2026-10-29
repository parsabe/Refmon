"""The human steps around the policy, end to end: keygen, sign, learn, approve, apply, load."""

from refmon.cli import main
from refmon.policy import default_policy
from refmon.policy_io import load_policy, read_document
from scenario_run import GOLDEN_DIR


def test_the_whole_flow_from_a_learning_run_to_a_signed_policy(tmp_path, capsys):
    key, policy, proposal, new = (
        tmp_path / n for n in ("key", "policy.yaml", "prop.yaml", "new.yaml")
    )
    assert main(["keygen", str(key)]) == 0
    public = capsys.readouterr().out.strip()
    assert main(["init-policy", str(policy)]) == 0
    assert main(["sign", str(policy), str(key)]) == 0
    assert main(["verify", str(policy), public]) == 0

    events = [str(GOLDEN_DIR / f"{s}.events.jsonl") for s in ("S11", "S26a", "S36")]
    assert main(["learn", str(policy), public, str(proposal), *events]) == 0
    assert main(["apply", str(policy), str(proposal), str(new), str(key)]) == 1  # not approved yet
    assert main(["approve", str(proposal), "--by", "alice", "--relax"]) == 0
    assert main(["apply", str(policy), str(proposal), str(new), str(key)]) == 0

    learned = load_policy(new, [public])
    assert learned.contract_for("interactive_shell").external_content_exec == "allow"
    assert default_policy().contract_for("interactive_shell").external_content_exec == "deny"
    assert "signature" in read_document(new)


def test_an_edited_policy_does_not_verify(tmp_path, capsys):
    key, policy = tmp_path / "key", tmp_path / "policy.yaml"
    main(["keygen", str(key)])
    public = capsys.readouterr().out.strip()
    main(["init-policy", str(policy)])
    main(["sign", str(policy), str(key)])
    policy.write_text(policy.read_text().replace("mode: observe", "mode: block"))
    assert main(["verify", str(policy), public]) == 1
