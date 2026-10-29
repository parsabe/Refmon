import hashlib
import hmac

import pytest

from evhelp import ev, raw
from refmon.pipeline.observe import Observe
from refmon.policy import default_policy

KEY = b"device-key"


@pytest.fixture
def observe():
    return Observe(default_policy(), KEY)


def test_content_becomes_an_hmac_sha256_fingerprint_under_the_device_key(observe):
    out = observe(raw("exec", "interactive_shell", "p-1", content="echo  hello\n  world"))
    expected = hmac.new(
        KEY, b"echo hello world", hashlib.sha256
    ).hexdigest()  # whitespace normalised
    assert out.object.fingerprint == f"hmac:{expected}"
    other = Observe(default_policy(), b"another-key")
    assert (
        other(
            raw("exec", "interactive_shell", "p-1", content="echo hello world")
        ).object.fingerprint
        != out.object.fingerprint
    )


def test_empty_key_is_refused():
    with pytest.raises(ValueError):
        Observe(default_policy(), b"")


def test_no_raw_content_or_raw_attribute_survives(observe):
    secret = "zz-secret-command-zz"
    r = raw(
        "net_connect",
        "other",
        "p-1",
        content=secret,
        host="bad.example.invalid",
        ip="203.0.113.9",
        domain="lure.example.net",
        url_path="/zz-path",
        program="zz-prog",
        signer="zz-signer",
    )
    out = observe(r)
    text = out.to_json_line()
    for needle in (
        secret,
        "bad.example.invalid",
        "203.0.113.9",
        "lure.example.net",
        "zz-path",
        "zz-prog",
        "zz-signer",
    ):
        assert needle not in text


def test_an_already_observed_event_passes_through(observe):
    e = ev("exec", "other", "p-1", f=7)
    assert observe(e) is e


def test_a_sensor_cannot_set_the_outcome_attributes(observe):
    out = observe(
        raw(
            "content_in",
            "browser",
            "p-1",
            content="x",
            source_class="web",
            trusted_source="official-python-index",
            canary_hit=True,
            threat_list_hit="x",
        )
    )
    assert (
        "trusted_source" not in out.attrs
        and "canary_hit" not in out.attrs
        and "threat_list_hit" not in out.attrs
    )


@pytest.mark.parametrize(
    ("attrs", "role", "user", "expected"),
    [
        (
            {"source_class": "download", "domain": "pypi.org"},
            "package_installer",
            "u",
            "official-python-index",
        ),
        (
            {"source_class": "download", "domain": "files.pythonhosted.org"},
            "package_installer",
            "u",
            "official-python-index",
        ),
        (
            {"source_class": "web", "domain": "pypi.org"},
            "package_installer",
            "u",
            None,
        ),  # wrong source class
        ({"source_class": "download", "domain": "evil.example"}, "package_installer", "u", None),
        ({"source_class": "download"}, "package_installer", "u", None),  # no domain: no match
    ],
)
def test_trusted_source_matches_source_class_and_domain(observe, attrs, role, user, expected):
    out = observe(raw("content_in", role, "p-1", content="pkg", **attrs))
    assert out.attrs.get("trusted_source") == expected


def test_trusted_source_can_match_on_signer_role_and_group():
    policy = default_policy(
        trusted_sources=[
            {"name": "signed-by-it", "match": {"signer": ["it-ca"]}},
            {"name": "deploy-role", "match": {"actor_role": ["deploy_tool"]}},
            {"name": "research", "match": {"group": ["research-lab"]}},
        ],
        user_groups={"carol": "research-lab"},
    )
    obs = Observe(policy, KEY)
    assert (
        obs(raw("content_in", "package_installer", "p-1", content="a", signer="it-ca")).attrs[
            "trusted_source"
        ]
        == "signed-by-it"
    )
    assert (
        obs(raw("content_in", "deploy_tool", "p-2", content="b")).attrs["trusted_source"]
        == "deploy-role"
    )
    carol = raw("content_in", "package_installer", "p-3", content="c")
    assert "trusted_source" not in carol.attrs
    carol = carol.model_copy(update={"actor": carol.actor.model_copy(update={"user": "carol"})})
    assert obs(carol).attrs["trusted_source"] == "research"


@pytest.mark.parametrize(
    ("attrs", "expected"),
    [
        ({"host": "db.example.internal"}, "db_server"),
        ({"host": "DB.example.internal"}, "db_server"),
        ({"ip": "10.20.30.40"}, "internal_network"),
        ({"ip": "192.168.1.5"}, "internal_network"),
        ({"ip": "203.0.113.7"}, "unknown"),  # an IP-only connection that matches no CIDR
        ({"host": "never-heard-of.example"}, "unknown"),
        ({}, "unknown"),
        ({"ip": "not-an-ip"}, "unknown"),
    ],
)
def test_destination_class_by_host_or_cidr_and_unknown_otherwise(observe, attrs, expected):
    assert (
        observe(raw("net_connect", "other", "p-1", **attrs)).attrs["destination_class"] == expected
    )


def test_exec_class_from_the_program_name(observe):
    assert (
        observe(raw("exec", "office", "p-1", program="lpr")).attrs["exec_class"] == "print_helper"
    )
    assert observe(raw("exec", "office", "p-1", program="wscript")).attrs["exec_class"] == "unknown"
    assert observe(raw("exec", "office", "p-1")).attrs["exec_class"] == "unknown"


def test_protected_asset_by_class_and_by_path_group(observe):
    assert (
        observe(raw("asset_access", "other", "p-1", cls="credential_store")).attrs[
            "protected_asset"
        ]
        == "browser-passwords"
    )
    assert (
        observe(raw("asset_access", "other", "p-1", cls="config", path_group="app_secrets")).attrs[
            "protected_asset"
        ]
        == "app-config-secrets"
    )
    assert (
        "protected_asset" not in observe(raw("asset_access", "other", "p-1", cls="document")).attrs
    )


def test_threat_list_hit_is_confirmed_inside_observe_and_only_the_name_is_emitted(observe):
    hit = observe(raw("net_connect", "other", "p-1", host="bad.example.invalid"))
    assert hit.attrs["threat_list_hit"] == "known-bad-hosts"
    assert "bad.example.invalid" not in hit.to_json_line()
    assert (
        "threat_list_hit"
        not in observe(raw("net_connect", "other", "p-1", host="fine.example")).attrs
    )
    assert (
        observe(
            raw(
                "content_in",
                "browser",
                "p-1",
                content="x",
                domain="BAD.example.invalid",
                source_class="web",
            )
        ).attrs["threat_list_hit"]
        == "known-bad-hosts"
    )


def test_canary_url_path_is_matched_before_fingerprinting(observe):
    hit = observe(
        raw(
            "request_in",
            "web_worker",
            "p-1",
            content="GET /admin-backup-old/x",
            url_path="/admin-backup-old/login",
            source_class="inbound_request",
        )
    )
    assert hit.attrs["canary_hit"] is True
    assert "admin-backup-old" not in hit.to_json_line()
    assert (
        "canary_hit"
        not in observe(
            raw(
                "request_in", "web_worker", "p-1", url_path="/index", source_class="inbound_request"
            )
        ).attrs
    )


def test_canary_credential_is_matched_on_content(observe):
    assert (
        observe(
            raw(
                "asset_access", "other", "p-1", cls="credential_store", content="canary-db-password"
            )
        ).attrs["canary_hit"]
        is True
    )
    assert (
        "canary_hit"
        not in observe(
            raw("asset_access", "other", "p-1", cls="credential_store", content="real")
        ).attrs
    )


def test_signed_is_passed_through_from_the_sensor(observe):
    assert observe(raw("exec", "launcher", "p-1", signed="unknown")).attrs["signed"] == "unknown"
    assert observe(raw("exec", "launcher", "p-1", signed=False)).attrs["signed"] is False


def test_the_ring_buffer_holds_observed_events_for_at_most_the_buffer_age(observe):
    for t in (0, 100, 200, 700, 800):
        observe(raw("exec", "other", "p-1", content=f"cmd{t}", t=t))
    ages = [e.ts for e in observe.buffer]
    assert (ages[-1] - ages[0]).total_seconds() <= default_policy().thresholds.buffer_max_age
    assert len(observe.buffer) == 3  # t=200 is exactly... t=700 and t=800 plus t=200 within 600 s
    assert all(
        e.object.fingerprint is None or e.object.fingerprint.startswith("hmac:")
        for e in observe.buffer
    )
