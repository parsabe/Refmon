"""The reproduction and publishability scripts: the pieces that can be tested without replaying
everything. `make reproduce` itself is the end-to-end test and is run by hand and in the release
check."""

import re
import sys

import pytest

from scenario_run import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import check_publishable as cp
import reproduce as rp

BLOCKS = ["versions", "matrix", "stats", "golden", "coverage", "audit", "publishable", "tests"]


def test_every_generated_block_of_the_results_file_exists_once_and_is_closed():
    text = (ROOT / "docs" / "results.md").read_text()
    for name in BLOCKS:
        assert len(re.findall(rf"<!-- BEGIN GENERATED: {name} -->", text)) == 1, name
        assert len(re.findall(rf"<!-- END GENERATED: {name} -->", text)) == 1, name
    found = set(re.findall(r"<!-- BEGIN GENERATED: (\w+) -->", text))
    assert found == set(BLOCKS)


def test_replace_block_rewrites_only_its_block():
    text = "a\n<!-- BEGIN GENERATED: x -->\nold\n<!-- END GENERATED: x -->\nb\n"
    out = rp.replace_block(text, "x", "new\nlines")
    assert out == "a\n<!-- BEGIN GENERATED: x -->\nnew\nlines\n<!-- END GENERATED: x -->\nb\n"
    assert rp.replace_block(out, "x", "new\nlines") == out  # idempotent
    with pytest.raises(SystemExit):
        rp.replace_block(text, "missing", "z")


def test_the_tags_the_reproduction_needs_exist():
    import subprocess

    tags = subprocess.run(
        ["git", "-C", str(ROOT), "tag", "-l"], capture_output=True, text=True, check=True
    ).stdout.split()
    assert set(rp.TAGS) <= set(tags)


def findings(line):
    return cp.line_findings(line, {"labhost"})


def test_the_publishability_check_finds_what_it_should():
    assert findings("key = '-----BEGIN RSA PRIVATE KEY-----'")
    assert findings("aws AKIAABCDEFGHIJKLMNOP here")
    assert findings('password = "hunter2hunter2hunter2"')
    assert any("e-mail" in f for f in findings("write to someone@gmail.com"))
    assert any("home path" in f for f in findings("see /home/alice/projects"))
    assert any("public IP" in f for f in findings("connect 8.8.8.8"))
    assert any("url" in f for f in findings("fetch https://evil.org/x"))
    assert any("name of this machine" in f for f in findings("ssh labhost"))


def test_the_publishability_check_leaves_synthetic_data_alone():
    for line in (
        "bob@corp.example",
        "connect 10.1.2.3 and 192.168.0.9 and 203.0.113.5",
        "see https://pypi.org/project/x and http://x.invalid/a",
        'secret = "zz-secret-command-zz"',
        "plain prose with no data",
    ):
        assert findings(line) == [], line


def test_the_repository_itself_has_no_content_findings():
    names = cp.own_names()
    assert cp.scan_tree(names) == []
    count, bad = cp.scan_events()
    assert count > 300 and bad == []


def test_identities_are_masked_in_the_output_that_goes_into_the_results_file():
    masked = cp.mask("Jane Doe <jane.doe@university.edu>")
    assert "jane" not in masked.lower() and "university" not in masked and "@" in masked
    assert cp.mask("x <y@z.org>").endswith(".org>")


def test_the_results_file_holds_no_e_mail_address_at_all():
    text = (ROOT / "docs" / "results.md").read_text()
    assert not cp.EMAIL.search(text)
