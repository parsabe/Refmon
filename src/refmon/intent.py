r"""What a shell command line would do, for the live command barrier (`refmon guard`).

The live barrier judges a command *before* it runs, so it has to predict the behaviour the pipeline
would otherwise observe: which hosts it connects to, whether it writes a startup item, reads key
material, tampers with logs or with Refmon itself, changes privileges, injects a preload library or
changes many files at once. `analyze` names behaviours, never malware families or exploits; the
pipeline then judges them with the same contracts and weights as any other event.

This runs on the raw command in memory only (like Observe) and returns no raw text except the host
names and URL paths that Observe consumes and drops. It is a heuristic over command text: a command
that hides its intent (an interpreter reading a script file, a binary) shows only what its text
shows, which is why the live barrier is a mediation layer, not a complete sensor (docs/progress.md).

v2.0: the text is analysed twice, as written and after undoing the shell's own ways of hiding a word
(empty quotes inside a word, a backslash inside a word, `${IFS}` for a space, `$'\x..'` escapes,
quotes around a single word, and variables assigned earlier on the same line); a behaviour found in
either counts. Hiding a word in one of these ways is itself the `encoded` (hide) behaviour. New
behaviours: running fetched code through process substitution (`bash <(curl ...)`), git hooks as
persistence, containers with host privileges, reverse and dynamic SSH tunnels, and sending the home
directory or the file system root to a host (`exfil`).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?(/[^\s'\"|;&]*)?")
_PIPE_EXEC_RE = re.compile(
    r"\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k)?sh|python3?|perl)\b"
)
_ENCODE_RE = re.compile(r"\b(?:base64\b|-enc\b|fromhex\b|eval\s*\(|xxd\s+-r)")
# fetched code run through process substitution: bash <(curl ...), source <(...), . <(...)
_PROC_SUBST_EXEC_RE = re.compile(
    r"(?:\b(?:ba|z|da|k)?sh|\bsource|(?:^|[;&|]\s*)\.)\s+<\(\s*(?:curl|wget|nc|ncat|python3?)\b"
)
# a container that is given the host: privileged, the host root mounted, the host's process table
_CONTAINER_PRIV_RE = re.compile(
    r"\b(?:docker|podman)\s+(?:container\s+)?run\b[^;&|]*?"
    r"(?:--privileged\b|(?:-v|--volume)[= ]?/:|--pid[= ]host\b|--cap-add[= ](?:ALL|SYS_ADMIN)\b)"
)
_PRIV_RE = re.compile(r"(?:^|[;&|]\s*)(?:sudo|su)\b|\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\b")

# -- network ------------------------------------------------------------------------------------
_DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"]+)/\d+")
_SHELL_NET_RE = re.compile(
    r"\bztcp\s+(?:-\w+\s+)*([^\s'\";]+)\s+\d+|/inet[46]?/tcp/\d+/([^/\s'\"]+)/\d+"
    r"|\bs_client\b[^;&|]*-connect\s+([^:\s'\"]+):\d+"
)
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
    r"|\.aws/(?:credentials|config)(?![\w.-])|\.kube/config(?![\w.-])|\.netrc\b|\.git-credentials\b"
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
    r"|/etc/profile|/etc/ld\.so\.preload|\.git/hooks/|/var/spool/cron)"
)
_SCHEDULE_RE = re.compile(
    r"\bsystemctl\s+--user\s+(?:enable|link|edit)\b|(?:^|[;&|]\s*)at\s+(?:now|noon|midnight|\d)"
    r"|\bgit\s+config\b[^;&|]*\bcore\.hooksPath\b"
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
    r"\b(?:openssl\s+(?:enc|aes)|gpg\s+(?:--?[\w-]+\s+)*?(?:-c|--symmetric|-e|--encrypt)\b"
    r"|ccrypt|7z\s+a\s+-p|zip\s+-[eP])"
)

# -- sending the home directory or the root away (exfil) ----------------------------------------
_TREE = r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/)/?(?=\s|$|[;&|)])"
_ARCHIVE_TREE_RE = re.compile(r"\b(?:tar|zip|7z|cpio|rsync|scp)\b[^;&|]*\s" + _TREE)
_SENDERS = {"nc", "ncat", "netcat", "socat", "curl", "wget", "ssh", "scp", "rsync", "telnet"}

# -- the shell's own ways of hiding a word -----------------------------------------------------
_EMPTY_QUOTES_RE = re.compile(r"(?<=[\w./~-])(?:''|\"\")|(?:''|\"\")(?=[\w./~-])")
_WORD_BACKSLASH_RE = re.compile(r"(?<=[\w./~-])\\(?=[A-Za-z0-9])")
_IFS_RE = re.compile(r"\$\{IFS\}|\$IFS\b")
_ANSI_C_RE = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_QUOTED_WORD_RE = re.compile(r"\"([^\"\s]+)\"|'([^'\s]+)'")
_ASSIGN_RE = re.compile(r"(?:^|[;&|]\s*|\s)([A-Za-z_]\w*)=([^\s;&|'\"]+|'[^']*'|\"[^\"]*\")")
_QUOTED_TEXT_RE = re.compile(r"'[^']+'|\"[^\"]+\"")

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
    exfil: bool = False  # v2.0: the home directory or the root sent to a host

    @property
    def behaviours(self) -> list[str]:
        out = []
        if self.hosts:
            out.append("network")
        for name in ("encoded", "persist", "privilege", "preload", "bulk", "exfil"):
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


def _ansi_c(body: str) -> str:
    def one(m: re.Match) -> str:
        esc = m.group(1)
        try:
            if esc[0] == "x":
                return chr(int(esc[1:], 16))
            if esc[0].isdigit():
                return chr(int(esc, 8))
        except ValueError:
            return m.group(0)
        return {"n": "\n", "t": "\t"}.get(esc, esc)

    return re.sub(r"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)", one, body)


def normalize(cmd: str) -> tuple[str, bool]:
    """The command with the shell's word-hiding undone, and whether any was used to hide a word.

    Removing characters the shell itself removes never adds a behaviour that the shell would not
    see, so analysing this form as well as the written one only finds what the command does."""
    hidden = bool(
        _EMPTY_QUOTES_RE.search(cmd)
        or _WORD_BACKSLASH_RE.search(_QUOTED_TEXT_RE.sub(" ", cmd))
        or _IFS_RE.search(cmd)
        or re.search(r"\$'[^']*\\(?:x[0-9A-Fa-f]|[0-7])", cmd)
    )
    t = _ANSI_C_RE.sub(lambda m: _ansi_c(m.group(1)), cmd)
    t = _IFS_RE.sub(" ", t)
    t = _EMPTY_QUOTES_RE.sub("", t)
    t = _WORD_BACKSLASH_RE.sub("", t)
    t = _QUOTED_WORD_RE.sub(lambda m: m.group(1) or m.group(2), t)
    assigned = {m.group(1): m.group(2).strip("'\"") for m in _ASSIGN_RE.finditer(t)}
    if assigned:
        names = "|".join(re.escape(n) for n in sorted(assigned, key=len, reverse=True))
        before = t
        t = re.sub(r"\$\{(" + names + r")\}|\$(" + names + r")\b",
                   lambda m: assigned[m.group(1) or m.group(2)], t)  # fmt: skip
        # a program name assembled from variables hides the program
        for seg in _segments(before):
            prog = next((tok for tok in seg if "=" not in tok or tok.startswith(("/", "."))), "")
            if "$" in prog and not re.fullmatch(r"\$\{?\w+\}?", prog):
                hidden = True
    return t, hidden


def analyze(cmd: str) -> CommandIntent:
    written = _analyze_text(cmd.strip())
    plain, hidden = normalize(cmd.strip())
    seen = _analyze_text(plain) if plain != cmd.strip() else written
    out = CommandIntent(program=seen.program if seen.program != "sh" else written.program)
    for h in [*written.hosts, *seen.hosts]:
        _add(out.hosts, h)
    out.url_paths = list(dict.fromkeys([*written.url_paths, *seen.url_paths]))
    for name in ("encoded", "persist", "privilege", "preload", "bulk", "exfil"):
        setattr(out, name, getattr(written, name) or getattr(seen, name))
    out.encoded = out.encoded or hidden
    out.secret = (
        "canary" if "canary" in (written.secret, seen.secret) else written.secret or seen.secret
    )
    out.tamper = written.tamper or seen.tamper
    return out


def _analyze_text(text: str) -> CommandIntent:
    low = text.lower()
    segments = _segments(text)
    intent = CommandIntent(program=_program(segments[0]) if segments else "sh")

    for m in _URL_RE.finditer(text):
        _add(intent.hosts, m.group(1))
        path = m.group(2) or "/"
        if path not in intent.url_paths:
            intent.url_paths.append(path)
    for rx in (_DEV_TCP_RE, _SOCAT_RE, _SOCKET_CALL_RE, _SHELL_NET_RE):
        for m in rx.finditer(text):
            _add(intent.hosts, next(g for g in m.groups() if g))
    for toks in segments:
        if _program(toks) == "ssh" and any(
            re.fullmatch(r"-[A-Za-z]*[RD][A-Za-z]*", t) for t in toks[1:]
        ):  # a reverse or dynamic tunnel opens the host to the remote side
            for tok in toks[1:]:
                host = tok.rsplit("@", 1)[-1]
                if not tok.startswith("-") and _HOSTLIKE_RE.match(host):
                    _add(intent.hosts, host)
                    break
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

    intent.encoded = bool(
        _ENCODE_RE.search(text) or _PIPE_EXEC_RE.search(text) or _PROC_SUBST_EXEC_RE.search(text)
    )
    intent.privilege = bool(_PRIV_RE.search(low) or _CONTAINER_PRIV_RE.search(text))
    intent.preload = bool(_PRELOAD_RE.search(text))
    intent.bulk = bool(_BULK_DELETE_RE.search(text) or _BULK_ENCRYPT_RE.search(text))
    # the home directory or the root archived or copied, and the line sends something to a host
    progs = {_program(t) for t in segments}
    intent.exfil = bool(
        _ARCHIVE_TREE_RE.search(text) and (intent.hosts or ("@" in text and progs & _SENDERS))
    )

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
                if uses_keys and (tok == "-i" or (tok == "-f" and _program(toks) == "ssh-keygen")):
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
