"""What a shell command line would do, for the live command barrier (`refmon guard`).

The live barrier judges a command *before* it runs, so it has to predict the behaviour the pipeline
would otherwise observe: which hosts it connects to, whether it writes a startup item, reads key
material, tampers with logs or with Refmon itself, changes privileges, injects a preload library or
changes many files at once. `analyze` names behaviours, never malware families or exploits; the
pipeline then judges them with the same contracts and weights as any other event.

This runs on the raw command in memory only (like Observe) and returns no raw text except the host
names and URL paths that Observe consumes and drops. It is a heuristic over command text: a command
that hides its intent (an interpreter reading a script file, a binary) shows only what its text
shows, which is why the live barrier is a mediation layer, not a complete sensor (docs/progress.md).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?(/[^\s'\"|;&]*)?")
_PIPE_EXEC_RE = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*python3?\b|\|\s*perl\b")
_ENCODE_RE = re.compile(r"\b(?:base64\b|-enc\b|fromhex\b|eval\s*\(|xxd\s+-r)")
_PRIV_RE = re.compile(r"(?:^|[;&|]\s*)(?:sudo|su)\b|\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\b")

# -- network ------------------------------------------------------------------------------------
_DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"]+)/\d+")
_SOCAT_RE = re.compile(r"\b(?:tcp|udp|ssl|openssl)[46]?(?:-connect)?:([^:\s,'\"]+):\d+", re.I)
_SOCKET_CALL_RE = re.compile(
    r"(?:\.connect\(\(?|TCPSocket\.(?:new|open)\(|inet_aton\(|fsockopen\(|PeerAddr\s*=>\s*)"
    r"\s*['\"]([^'\":]+)"
)
_NET_TOOLS = {"nc", "ncat", "netcat", "telnet"}
_HOSTLIKE_RE = re.compile(r"^(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")

# -- key material and secrets ---------------------------------------------------------------------
_CANARY = ("canary-db.conf", "canary-db-password")
_SECRET_RE = re.compile(
    r"(?:/etc/(?:g?shadow|sudoers)\b|app_secrets|passwords?\b|\.kdbx\b"
    r"|\.ssh/id_[A-Za-z0-9]+(?!\.pub)\b|\.ssh/[^\s/]*_key\b(?!\.pub)"
    r"|\.aws/(?:credentials|config)\b|\.kube/config\b|\.netrc\b|\.git-credentials\b"
    r"|\.docker/config\.json\b|\.pgpass\b|\.gnupg/|\.password-store/|\.config/gcloud/|\.azure/"
    r"|\.vault-token\b)"
)
# programs that legitimately *use* a key given with -i (the key is not read out)
_KEY_USERS = {"ssh", "scp", "sftp", "rsync", "git", "ssh-add", "ssh-keygen", "ssh-copy-id"}

# -- persistence ---------------------------------------------------------------------------------
_STARTUP_RE = re.compile(
    r"(?:\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.zshenv|\.xinitrc"
    r"|\.config/autostart/|\.config/systemd/user/|\.config/fish/config\.fish"
    r"|\.ssh/authorized_keys2?|\.ssh/rc\b|/etc/systemd/system/|/etc/cron|/etc/rc\.local"
    r"|/etc/profile|/etc/ld\.so\.preload)"
)
_SCHEDULE_RE = re.compile(
    r"\bsystemctl\s+--user\s+(?:enable|link|edit)\b|(?:^|[;&|]\s*)at\s+(?:now|noon|midnight|\d)"
)

# -- tampering ----------------------------------------------------------------------------------
_SELF_FILES = r"(?:refmon-live|\.refmon\b|policy\.yaml|admin\.key|device\.key|api\.token)"
_SELF_TAMPER_RE = re.compile(
    r"\b(?:pkill|killall)\b[^;&|]*refmon|\bkill\b[^;&]*refmon"
    r"|\b(?:rm|mv|chmod|chown|truncate|shred|sed|tee|cp|ln)\b[^;&|]*"
    + _SELF_FILES
    + r"|>\s*\S*"
    + _SELF_FILES
)
_SECURITY_TAMPER_RE = re.compile(
    r"\bsystemctl\s+(?:stop|disable|mask)\b(?!\s+--user)|\bufw\s+disable\b|\biptables\s+-F\b"
    r"|\bsetenforce\s+0\b|\bauditctl\s+-D\b"
)
_LOG_TAMPER_RE = re.compile(
    r"\bhistory\s+-[cwd]\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHISTSIZE=0\b"
    r"|\bset\s+\+o\s+history\b"
    r"|(?:\b(?:rm|shred|truncate|ln\s+-sf\s+/dev/null)\b[^;&|]*|>\s*)"
    r"(?:\S*\.(?:bash|zsh|python|mysql|psql|lesshst)_?history|/var/log/)"
)

# -- preload injection --------------------------------------------------------------------------
_PRELOAD_RE = re.compile(
    r"\b(?:LD_PRELOAD|LD_AUDIT)=['\"]?(?:/tmp/|/dev/shm/|/var/tmp/|\./|\.\./|\$PWD/)"
)

# -- many files at once (destruction or encryption) --------------------------------------------
_HOME_OR_ROOT = r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/)/?\*?"
_BULK_DELETE_RE = re.compile(
    r"\brm\s+(?:-[A-Za-z]*[rR][A-Za-z]*\s+|--no-preserve-root\s+|-[A-Za-z]+\s+)+"
    + _HOME_OR_ROOT
    + r"(?=\s|$|[;&|])"
    r"|\bfind\s+" + _HOME_OR_ROOT + r"\s[^;&|]*(?:-delete\b|-exec\s+(?:rm|shred)\b)"
)
_BULK_ENCRYPT_RE = re.compile(
    r"(?:\bfind\b|\bxargs\b|\bfor\s+\w+\s+in\b|\bwhile\b)[^\n]*"
    r"\b(?:openssl\s+(?:enc|aes)|gpg\s+(?:-c|--symmetric|-e|--encrypt)|ccrypt|7z\s+a\s+-p|zip\s+-[eP])"
)

_SEGMENT_RE = re.compile(r"\s*(?:\|\||&&|;|\||&)\s*")
_REDIRECT_RE = re.compile(r"(?:\d?>>?|&>>?)\s*(['\"]?)([^\s;&|'\"]+)\1")


@dataclass
class CommandIntent:
    program: str = "sh"
    hosts: list[str] = field(default_factory=list)
    url_paths: list[str] = field(default_factory=list)
    encoded: bool = False
    secret: str | None = None  # "canary" or "secret"
    persist: bool = False
    tamper: str | None = None  # "self", "security" or "logs"
    privilege: bool = False
    preload: bool = False
    bulk: bool = False

    @property
    def behaviours(self) -> list[str]:
        out = []
        if self.hosts:
            out.append("network")
        for name in ("encoded", "persist", "privilege", "preload", "bulk"):
            if getattr(self, name):
                out.append(name)
        if self.secret:
            out.append(f"secret:{self.secret}")
        if self.tamper:
            out.append(f"tamper:{self.tamper}")
        return out


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return segment.split()


def _program(tokens: list[str]) -> str:
    for tok in tokens:
        if "=" in tok and not tok.startswith(("/", ".")):
            continue  # VAR=value prefix
        return PurePosixPath(tok).name
    return "sh"


def _segments(cmd: str) -> list[list[str]]:
    return [t for t in (_tokens(s) for s in _SEGMENT_RE.split(cmd) if s.strip()) if t]


def _add(hosts: list[str], host: str) -> None:
    host = host.strip("[]'\"")
    if host and host not in hosts and host.lower() not in {"localhost", "127.0.0.1", "::1"}:
        hosts.append(host)


def _write_targets(cmd: str, segments: list[list[str]]) -> list[str]:
    targets = [m.group(2) for m in _REDIRECT_RE.finditer(cmd)]
    for toks in segments:
        prog = _program(toks)
        args = [t for t in toks[1:] if not t.startswith("-")]
        if prog == "tee":
            targets += args
        elif (prog in {"cp", "mv", "install", "ln", "rsync"} and len(args) >= 2) or (
            prog == "sed" and any(t.startswith("-i") for t in toks[1:]) and args
        ):
            targets.append(args[-1])  # the destination, or the file edited in place
        elif prog == "dd":
            targets += [t[3:] for t in toks[1:] if t.startswith("of=")]
    return targets


def analyze(cmd: str) -> CommandIntent:
    text = cmd.strip()
    low = text.lower()
    segments = _segments(text)
    intent = CommandIntent(program=_program(segments[0]) if segments else "sh")

    for m in _URL_RE.finditer(text):
        _add(intent.hosts, m.group(1))
        path = m.group(2) or "/"
        if path not in intent.url_paths:
            intent.url_paths.append(path)
    for rx in (_DEV_TCP_RE, _SOCAT_RE, _SOCKET_CALL_RE):
        for m in rx.finditer(text):
            _add(intent.hosts, m.group(1))
    for toks in segments:
        if _program(toks) in _NET_TOOLS:
            skip_next = False
            for tok in toks[1:]:
                if skip_next:
                    skip_next = False
                    continue
                if tok in {"-e", "-c", "-p", "-s", "-w", "-i", "-x", "--exec", "--sh-exec"}:
                    skip_next = True
                    continue
                if _HOSTLIKE_RE.match(tok):
                    _add(intent.hosts, tok)
                    break

    intent.encoded = bool(_ENCODE_RE.search(text) or _PIPE_EXEC_RE.search(text))
    intent.privilege = bool(_PRIV_RE.search(low))
    intent.preload = bool(_PRELOAD_RE.search(text))
    intent.bulk = bool(_BULK_DELETE_RE.search(text) or _BULK_ENCRYPT_RE.search(text))

    if any(c in low for c in _CANARY):
        intent.secret = "canary"
    else:
        # a key handed to ssh, scp, git, ... with -i is used, not read out
        scrubbed = []
        for toks in segments:
            keep, skip = [], False
            uses_keys = _program(toks) in _KEY_USERS
            for tok in toks:
                if skip:
                    skip = False
                    continue
                if uses_keys and tok == "-i":
                    skip = True
                    continue
                keep.append(tok)
            scrubbed.append(" ".join(keep))
        if _SECRET_RE.search(" ; ".join(scrubbed)):
            intent.secret = "secret"

    targets = _write_targets(text, segments)
    intent.persist = any(_STARTUP_RE.search(t) for t in targets) or bool(_SCHEDULE_RE.search(text))
    for toks in segments:
        if _program(toks) == "crontab" and not ({"-l", "-r"} & set(toks[1:])):
            intent.persist = True

    if _SELF_TAMPER_RE.search(text):
        intent.tamper = "self"
    elif _SECURITY_TAMPER_RE.search(low):
        intent.tamper = "security"
    elif _LOG_TAMPER_RE.search(text):
        intent.tamper = "logs"
    return intent
