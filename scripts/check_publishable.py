"""Check that the repository can be published: no secrets, no personal data, no raw content, in the
working tree (tracked files) or in the history of any ref.

    python scripts/check_publishable.py            # exit 1 on a content finding
    python scripts/check_publishable.py --strict   # also exit 1 on an identity in the history

What it looks for:
  * secrets: private keys, cloud and chat tokens, `password = "..."` style assignments;
  * personal data in content: e-mail addresses (except synthetic example domains), home-directory
    paths, user and host names of the machines the work was done on, public IP addresses, URLs;
  * raw content: every `*.events.jsonl` must parse as post-Observe `Event`s (fingerprints only, an
    allowlist of attribute keys, no `content` field);
  * identities: the author and committer names and e-mail addresses recorded by git in any ref.
    These are not content, they are metadata; they are reported (masked) because publishing the
    history publishes them, and only the owner can decide that.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SECRET = re.compile(
    r"BEGIN (?:RSA |EC |OPENSSH |ED25519 |DSA |)PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}"
    r"|AIza[0-9A-Za-z_-]{35}"
)
ASSIGNED = re.compile(
    r"(?i)\b(?:api[_-]?key|passwd|password|secret|token)\b\s*[:=]\s*['\"][A-Za-z0-9+/_=.-]{12,}['\"]"
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SYNTHETIC_MAIL = re.compile(r"@(?:[\w.-]*\.)?(?:example|invalid|test|localhost)(?:\.\w+)?$")
HOME = re.compile(r"/home/[a-z][a-z0-9_-]*|/Users/[A-Za-z][\w-]*|/root/")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PRIVATE_IP = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|203\.0\.113\.|198\.51\.100\.|"
    r"192\.0\.2\.|255\.)"
)
URL = re.compile(r"https?://[A-Za-z0-9./_?=&%#:@-]+")
OK_URL = re.compile(
    r"example\.|\.invalid|\.test\b|localhost|github\.com/actions|pypi\.org|python\.org|"
    r"claude\.(?:com|ai)|docs\.pytest|hypothesis|astral\.sh|keepachangelog|semver|json-schema|"
    r"github\.com/(?:astral-sh|pytest|HypothesisWorks)|"
    # the verbatim GPL-3.0 text in LICENSE
    r"//fsf\.org/|//www\.gnu\.org/licenses/"
)
# Machine and account names of the places the work was done on; filled from the environment, so
# the script never contains them.
# Strings the privacy tests plant on purpose, to prove that nothing leaks them; they are made up and
# look like a secret only because the test variable is called `secret`.
SYNTHETIC_MARKERS = ("zz-secret-command-zz", "zx9lab-obfuscated-payload")
# This script and its test contain the patterns they look for, on purpose.
SELF = {"scripts/check_publishable.py", "tests/test_reproduce.py"}
SKIP_SUFFIXES = {".pyc", ".png", ".jpg", ".gif", ".ico", ".pdf", ".zip", ".gz"}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=True,
        capture_output=True,
        text=True,
        errors="replace",
    ).stdout


def own_names() -> set[str]:
    """The login and host name of this machine, which must not appear in the repository. Skipped in
    CI, where they are generic words ("runner")."""
    import getpass
    import os
    import socket

    if os.environ.get("CI"):
        return set()
    names = {getpass.getuser(), socket.gethostname().split(".")[0]}
    return {n for n in names if len(n) >= 4}


def line_findings(line: str, names: set[str]) -> list[str]:
    if any(marker in line for marker in SYNTHETIC_MARKERS):
        return []
    out = []
    if SECRET.search(line) or ASSIGNED.search(line):
        out.append("secret")
    for m in EMAIL.finditer(line):
        if not SYNTHETIC_MAIL.search(m.group(0)):
            out.append(f"e-mail address {mask_email(m.group(0))}")
    if HOME.search(line):
        out.append("home path")
    for m in IPV4.finditer(line):
        if not PRIVATE_IP.match(m.group(0)):
            out.append(f"public IP {m.group(0)}")
    for m in URL.finditer(line):
        if not OK_URL.search(m.group(0)):
            out.append(f"url {m.group(0)[:60]}")
    for name in names:
        if re.search(rf"\b{re.escape(name)}\b", line):
            out.append("a user or host name of this machine")
    return out


def scan_tree(names: set[str]) -> list[str]:
    findings = []
    for rel in git("ls-files").splitlines():
        path = ROOT / rel
        if path.suffix in SKIP_SUFFIXES or not path.is_file() or rel in SELF:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for no, line in enumerate(text.splitlines(), 1):
            for kind in line_findings(line, names):
                findings.append(f"{rel}:{no}: {kind}")
    return findings


def scan_history(names: set[str]) -> list[str]:
    findings: Counter[str] = Counter()
    log = git("log", "--all", "-p", "--no-color", "--format=commit %h")
    commit, skip = "", False
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1]
        elif line.startswith("diff --git "):
            skip = line.split(" b/")[-1] in SELF
        elif line.startswith("+") and not line.startswith("+++") and not skip:
            for kind in line_findings(line[1:], names):
                findings[f"{commit}: {kind}"] += 1
    return sorted(findings)


def scan_events() -> tuple[int, list[str]]:
    """Every replay file must be post-Observe events: fingerprints only, allowlisted attributes."""
    sys.path.insert(0, str(ROOT / "src"))
    from refmon.policy import default_policy
    from refmon.schemas import Event

    roles = tuple(default_policy().extra_roles)
    bad, count = [], 0
    for path in sorted(ROOT.glob("tests/**/*.events.jsonl")):
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            count += 1
            try:
                Event.from_json_line(line, extra_roles=roles)
            except Exception as error:  # a pydantic ValidationError names the offending field
                bad.append(f"{path.relative_to(ROOT)}:{no}: {str(error).splitlines()[0][:80]}")
    return count, bad


def mask_email(address: str) -> str:
    local, _, domain = address.partition("@")
    host, _, tld = domain.rpartition(".")
    return f"{local[:1]}***@{host[:1]}***.{tld}"


def mask(identity: str) -> str:
    """`Name <local@domain.tld>` -> `N***e <l***@d***.tld>`: enough to recognise, not to publish."""

    def part(text: str) -> str:
        return text if len(text) < 3 else f"{text[0]}***{text[-1] if len(text) > 4 else ''}"

    name, _, rest = identity.partition(" <")
    local, _, domain = rest.rstrip(">").partition("@")
    host, _, tld = domain.rpartition(".")
    return f"{part(name)} <{part(local)}@{part(host)}.{tld}>"


def identities() -> Counter[str]:
    out: Counter[str] = Counter()
    for line in git("log", "--all", "--format=%an <%ae>%n%cn <%ce>").splitlines():
        if line.strip():
            out[line.strip()] += 1
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="a person's identity is a failure")
    args = parser.parse_args(argv)
    names = own_names()
    tree, history = scan_tree(names), scan_history(names)
    events, bad_events = scan_events()
    who = identities()
    print(f"tracked files scanned: {len(git('ls-files').splitlines())}, history: every ref")
    print(f"findings in the working tree: {len(tree)}")
    for f in tree[:20]:
        print(f"  {f}")
    print(f"findings in the history (added lines of every commit of every ref): {len(history)}")
    for f in history[:20]:
        print(f"  {f}")
    print(f"replay events checked as post-Observe events: {events}, rejected: {len(bad_events)}")
    for f in bad_events[:20]:
        print(f"  {f}")
    print(
        f"identities recorded by git as author or committer: {len(who)} "
        "(masked here so that this output can be published)"
    )
    for name in sorted(who):
        print(f"  {mask(name)}")
    content_ok = not (tree or history or bad_events)
    print("content: " + ("CLEAN" if content_ok else "FINDINGS"))
    print(
        "identities: "
        + ("none" if not who else "present in the history, the owner decides before publishing")
    )
    if not content_ok:
        return 1
    return 1 if (args.strict and who) else 0


if __name__ == "__main__":
    raise SystemExit(main())
