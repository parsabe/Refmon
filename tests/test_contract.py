import pytest
from pydantic import ValidationError

from refmon.schemas import Contract


def test_contract_distinguishes_unconstrained_from_nothing_allowed():
    web = Contract.model_validate(
        {
            "role": "web_worker",
            "may_exec": [],
            "may_write": ["cache", "sessions", "uploads_non_executable"],
            "may_connect": ["db_server", "cache_server"],
            "may_read_assets": [],
        }
    )
    assert web.may_exec == ()  # never spawns processes
    assert web.may_persist is None  # not constrained
    shell = Contract.model_validate({"role": "interactive_shell", "external_content_exec": "deny"})
    assert shell.may_exec is None
    assert shell.external_content_exec == "deny"


def test_contract_role_must_be_known_or_added_by_policy():
    with pytest.raises(ValidationError):
        Contract.model_validate({"role": "build_agent"})
    parsed = Contract.model_validate(
        {"role": "build_agent"}, context={"extra_roles": ["build_agent"]}
    )
    assert parsed.role == "build_agent"


def test_contract_rejects_bad_external_exec_value():
    with pytest.raises(ValidationError):
        Contract.model_validate({"role": "agent", "external_content_exec": "maybe"})


def test_package_installer_contract_from_the_spec():
    parsed = Contract.model_validate(
        {"role": "package_installer", "may_connect": ["package_index"], "may_persist": False}
    )
    assert parsed.may_persist is False


def test_universal_behaviours_are_forbidden_unless_the_contract_allows_them():
    plain = Contract.model_validate({"role": "web_worker"})
    assert not (plain.may_tamper or plain.may_mass_change)
    assert not (plain.may_fan_out or plain.may_repeat_large_responses)
    backup = Contract.model_validate(
        {"role": "backup_job", "may_mass_change": True}, context={"extra_roles": ["backup_job"]}
    )
    assert backup.may_mass_change is True
    assert backup.may_tamper is False  # allowing one behaviour allows no other


def test_universal_fields_are_booleans_not_unconstrained():
    with pytest.raises(ValidationError):
        Contract.model_validate({"role": "agent", "may_tamper": None})


def test_launcher_contract_can_deny_unsigned_external_exec():
    launcher = Contract.model_validate({"role": "launcher", "unsigned_external_exec": "deny"})
    assert launcher.unsigned_external_exec == "deny"
    assert Contract.model_validate({"role": "launcher"}).unsigned_external_exec is None
    with pytest.raises(ValidationError):
        Contract.model_validate({"role": "launcher", "unsigned_external_exec": "sometimes"})
