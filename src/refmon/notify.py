"""Notifications of the live daemon: a block, a hold waiting for an answer, a protection that
stopped working, a rejected policy, a rootkit finding, the daemon starting and stopping.

Privacy (CLAUDE.md Part A): a notification is built from fixed phrases, identifiers, pseudonyms and
numbers only, like a verdict that leaves the device. It never carries a command, a path, a URL or a
user name. The device is named by pseudonym.

Channels. Every notification goes to `logs/notifications.jsonl` and to the daemon's terminal.
External channels (a webhook, a command) receive only the categories they ask for, and are delivered
by one background thread so that a slow or dead endpoint never delays a decision. A failed delivery
is logged and counted; it does not raise a notification of its own (that would loop).
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TextIO

# What a notification is about. External channels filter on these.
CATEGORIES = ("block", "hold", "alert", "degraded", "rootkit", "lifecycle")
DEFAULT_EXTERNAL = ("block", "hold", "alert", "rootkit", "lifecycle")
SEVERITIES = ("critical", "warning", "info")


@dataclass(frozen=True)
class Notification:
    category: str  # one of CATEGORIES
    severity: str  # critical | warning | info
    title: str
    message: str
    device: str  # a pseudonym
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown notification category {self.category!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown notification severity {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "refmon",
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "device": self.device,
            "ts": self.ts.isoformat(timespec="seconds"),
            "details": self.details,
        }

    def text(self) -> str:
        return f"[Refmon {self.severity.upper()}] {self.title}: {self.message}"


class Channel(Protocol):
    name: str

    def deliver(self, note: Notification) -> None: ...


class LogChannel:
    """Append-only JSON Lines file; always on."""

    name = "log"

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def deliver(self, note: Notification) -> None:
        line = json.dumps(note.to_dict(), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


class ConsoleChannel:
    """One line on the daemon's terminal (stderr); always on."""

    name = "console"

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream

    def deliver(self, note: Notification) -> None:
        stream = self.stream if self.stream is not None else sys.stderr
        stamp = note.ts.astimezone(UTC).strftime("%H:%M:%S")
        print(f"[{stamp}] {note.text()}", file=stream, flush=True)


class WebhookChannel:
    """HTTP POST of `{"text": ..., "refmon": {...}}`: Slack, Mattermost and Rocket.Chat incoming
    webhooks show `text`; anything else can read the `refmon` object."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        if not url.startswith(("https://", "http://")):
            raise ValueError("the webhook URL must start with https:// or http://")
        self.url = url
        self.timeout = timeout

    def deliver(self, note: Notification) -> None:
        body = json.dumps({"text": note.text(), "refmon": note.to_dict()}).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            if resp.status >= 300:
                raise OSError(f"webhook answered HTTP {resp.status}")


class CommandChannel:
    """Runs a program (no shell) with the notification as JSON on stdin and the headline in
    REFMON_TITLE, REFMON_SEVERITY, REFMON_CATEGORY and REFMON_TEXT. Covers mail, wall, ntfy,
    notify-send or a site script, e.g. `--notify-command 'mail -s Refmon you@example.org'`."""

    name = "command"

    def __init__(self, argv: list[str], timeout: float = 10.0) -> None:
        if not argv:
            raise ValueError("the notify command is empty")
        self.argv = argv
        self.timeout = timeout

    def deliver(self, note: Notification) -> None:
        env = {
            **os.environ,
            "REFMON_TITLE": note.title,
            "REFMON_SEVERITY": note.severity,
            "REFMON_CATEGORY": note.category,
            "REFMON_TEXT": note.text(),
        }
        res = subprocess.run(
            self.argv,
            input=json.dumps(note.to_dict(), indent=2) + "\n",
            text=True,
            capture_output=True,
            timeout=self.timeout,
            env=env,
            check=False,
        )
        if res.returncode != 0:
            raise OSError(f"notify command exited with {res.returncode}")


class NotificationHub:
    """Sends each notification to the local channels at once and to the external ones in the
    background. A notification with a `key` already sent within `dedupe_s` is dropped."""

    def __init__(
        self,
        *,
        local: Iterable[Channel] = (),
        external: Iterable[Channel] = (),
        external_categories: Iterable[str] = DEFAULT_EXTERNAL,
        dedupe_s: float = 600.0,
        on_failure: Callable[[str], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.local = list(local)
        self.external = list(external)
        cats = set(external_categories)
        unknown = cats - set(CATEGORIES)
        if unknown:
            raise ValueError(f"unknown notification categories: {', '.join(sorted(unknown))}")
        self.external_categories = cats
        self.dedupe_s = dedupe_s
        self.on_failure = on_failure
        self.clock = clock
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.history: list[Notification] = []  # the last 50, for the dashboard
        self._recent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue[Notification | None] = queue.Queue(maxsize=500)
        self._worker: threading.Thread | None = None

    def describe(self) -> str:
        names = [c.name for c in self.external]
        if not names:
            return "log file and terminal only (no --notify-webhook or --notify-command)"
        cats = ", ".join(sorted(self.external_categories))
        return f"log, terminal, {', '.join(names)} (external: {cats})"

    def send(self, note: Notification, key: str | None = None) -> bool:
        """True when the notification was sent (not a duplicate)."""
        with self._lock:
            now = self.clock()
            if key is not None:
                last = self._recent.get(key)
                if last is not None and now - last < self.dedupe_s:
                    return False
                self._recent[key] = now
                if len(self._recent) > 5000:  # bounded: a daemon runs for weeks
                    cutoff = now - self.dedupe_s
                    self._recent = {k: t for k, t in self._recent.items() if t >= cutoff}
            self.history.append(note)
            del self.history[:-50]
        for channel in self.local:
            self._deliver(channel, note)
        if self.external and note.category in self.external_categories:
            self._ensure_worker()
            try:
                self._queue.put_nowait(note)
            except queue.Full:
                with self._lock:
                    self.dropped += 1
                self._fail("notification queue full: external delivery dropped")
        return True

    def _deliver(self, channel: Channel, note: Notification) -> None:
        try:
            channel.deliver(note)
        except (OSError, subprocess.SubprocessError, urllib.error.URLError, ValueError) as exc:
            with self._lock:
                self.failed += 1
            self._fail(f"notification via {channel.name} failed: {type(exc).__name__}: {exc}")
        else:
            with self._lock:
                self.sent += 1

    def _fail(self, message: str) -> None:
        if self.on_failure is not None:
            with contextlib.suppress(OSError):
                self.on_failure(message)

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(target=self._run, name="refmon-notifier", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            note = self._queue.get()
            try:
                if note is None:
                    return
                for channel in self.external:
                    self._deliver(channel, note)
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 15.0) -> bool:
        """Wait until every queued external notification was tried. True when done in time."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)
        return True

    def close(self, timeout: float = 15.0) -> None:
        self.flush(timeout)
        if self._worker is not None and self._worker.is_alive():
            self._queue.put(None)
            self._worker.join(timeout=2.0)


def parse_categories(text: str | None) -> tuple[str, ...]:
    if text is None or not text.strip():
        return DEFAULT_EXTERNAL
    if text.strip() == "all":
        return CATEGORIES
    return tuple(part.strip() for part in text.split(",") if part.strip())
