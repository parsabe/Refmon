"""The privacy audit (CLAUDE.md Phase 4 "Done when": zero raw content and zero reversals), plus
checks that the audit would notice a leak or a reversal."""

import hashlib
import hmac

from refmon import audit
from refmon.audit import (
    COMMON_COMMANDS,
    SECRETS,
    candidates,
    generic_findings,
    raw_corpus,
    run_audit,
    template_vocabulary,
    text_fields,
)
from refmon.keys import new_device_key
from refmon.pipeline import Pipeline
from refmon.pipeline.observe import normalize
from refmon.policy import default_policy
from scenario_run import GOLDEN_DIR


def test_done_when_the_audit_finds_zero_raw_content_and_zero_reversals():
    result = run_audit(GOLDEN_DIR)
    assert result.raw_findings == []
    assert result.reversals == []
    assert result.reid_successes == []
    assert result.ok, result.render()


def test_the_attack_is_real_it_reverses_fingerprints_when_the_key_is_known():
    result = run_audit(GOLDEN_DIR)
    assert result.control_reversals > 0
    assert result.reversal_attempts > 1000 and result.fingerprints > 100


def test_the_audit_log_chain_is_intact_and_covers_every_attempt():
    result = run_audit(None)
    assert result.audit_chain_ok and result.reid_attempts >= 9 and result.reid_legitimate_ok


def test_the_main_function_returns_zero_on_a_pass(capsys):
    assert audit.main([str(GOLDEN_DIR)]) == 0
    assert "PASS" in capsys.readouterr().out


# -- the scanner is not blind ---------------------------------------------------------------------------


def test_generic_patterns_catch_the_things_that_must_not_leave():
    for leak, kind in [
        ("fetched http://x.invalid/a", "url"),
        (r"wrote C:\Users\bob\a.exe", "windows path"),
        ("read /etc/passwd now", "unix path"),
        ("connected to 203.0.113.9", "ip address"),
        ("mail bob@corp.example", "e-mail"),
        ("host evil.example.com", "domain"),
        ("ran powershell -enc", "command word"),
        ("blob " + "QUJD" * 12, "encoded blob"),
    ]:
        assert kind in generic_findings(leak), leak
    clean = "A program started from something that came in from a web page. hmac:" + "ab" * 32
    assert generic_findings(clean) == []


def test_free_text_outside_the_templates_is_noticed():
    vocab = template_vocabulary()
    assert "program" in vocab and "quarantine" in vocab
    assert "mimikatz" not in vocab
    objects = [{"summary": "ok", "nested": [{"text": "the user typed mimikatz"}]}]
    assert text_fields(objects) == ["ok", "the user typed mimikatz"]


def test_a_leak_through_a_verdict_would_be_found_by_the_secret_scan():
    # Observe drops every raw value: none of the lab secrets survives into any stored form
    pipe = Pipeline(default_policy(mode="block"), new_device_key(), gate=True)
    blobs = []
    for event in raw_corpus():
        for out in pipe.process(event):
            blobs.append(out.model_dump_json())
    blobs += [e.to_json_line() for e in pipe.observe.buffer]
    text = " ".join(blobs).lower()
    secrets = [s for values in SECRETS.values() for s in values]
    assert secrets and not [s for s in secrets if s.lower() in text]
    # the same scan finds a secret that is planted
    assert [s for s in secrets if s.lower() in (text + " " + secrets[0].lower())]


def test_the_dictionary_would_reverse_a_fingerprint_made_with_a_guessable_key():
    word = normalize(COMMON_COMMANDS[0])
    weak = "hmac:" + hmac.new(b"key", word.encode(), hashlib.sha256).hexdigest()
    found = [
        w
        for w in candidates()
        if "hmac:" + hmac.new(b"key", w.encode(), hashlib.sha256).hexdigest() == weak
    ]
    assert found == [word]


def test_a_random_device_key_is_random_and_long_enough():
    assert new_device_key() != new_device_key()
    assert len(new_device_key()) == 32
