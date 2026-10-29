"""Builds the golden event streams. Run `python tests/golden_builder.py` to rewrite them, or with
`--check` to fail if the committed files differ.

Everything here is a harmless stand-in: fingerprints are HMACs of placeholder labels such as
"s01.clipboard", never of a real command, request or payload. The expected verdicts
(`*.expected.json`) of S01-S14 are written by hand; the rest are declared in golden_more.META.
"""

import json
import sys
from collections.abc import Callable

import golden_more
from golden_dsl import (  # noqa: F401
    ENDPOINT,
    GOLDEN_DIR,
    LAB_KEY,
    SERVER,
    START,
    Stream,
    actor,
    fp,
)
from refmon.schemas import Event


def s01() -> list[Event]:
    """Fake CAPTCHA: a web page puts a command on the clipboard, the user pastes it into the
    run dialog, a hidden shell starts a script host that fetches and drops an executable."""
    browser = actor("p-100", "browser", "alice", interactive=True)
    run_dialog = actor("p-210", "launcher", "alice", interactive=True)
    shell = actor("p-211", "interactive_shell", "alice", parent="p-210")
    script = actor("p-212", "script_host", "alice", parent="p-211")
    s = Stream(ENDPOINT)
    s.add(
        0,
        "content_in",
        browser,
        "web_page",
        "s01.page",
        source_class="web",
    )
    s.add(
        900,
        "content_in",
        browser,
        "clipboard_text",
        "s01.clipboard",
        source_class="web",
    )
    s.add(6200, "user_input", run_dialog, "command_text", "s01.clipboard", input_method="paste")
    s.add(350, "exec", run_dialog, "command_text", "s01.clipboard", launched_via="run_dialog")
    s.add(400, "exec", shell, "command_text", "s01.inner", hidden_window=True, encoded_payload=True)
    s.add(
        800,
        "net_connect",
        script,
        "network_endpoint",
        "s01.dest",
        destination_class="unknown",
    )
    s.add(
        1500,
        "file_write",
        script,
        "executable_file",
        "s01.dropped",
        path_group="temp_dir",
        executable=True,
        new_file=True,
    )
    return s.events


def s02() -> list[Event]:
    """Same lure, pasted into a terminal; the payload fetches, drops a file and persists."""
    browser = actor("p-100", "browser", "alice", interactive=True)
    shell = actor("p-301", "interactive_shell", "alice", parent="p-300", interactive=True)
    script = actor("p-302", "script_host", "alice", parent="p-301")
    s = Stream(ENDPOINT)
    s.add(
        0,
        "content_in",
        browser,
        "web_page",
        "s02.page",
        source_class="web",
    )
    s.add(
        900,
        "content_in",
        browser,
        "clipboard_text",
        "s02.clipboard",
        source_class="web",
    )
    s.add(5400, "user_input", shell, "command_text", "s02.clipboard", input_method="paste")
    s.add(300, "exec", shell, "command_text", "s02.clipboard")
    s.add(
        700,
        "net_connect",
        script,
        "network_endpoint",
        "s02.dest",
        destination_class="unknown",
    )
    s.add(
        1200,
        "file_write",
        script,
        "executable_file",
        "s02.dropped",
        path_group="temp_dir",
        executable=True,
        new_file=True,
    )
    s.add(600, "persist", script, "startup_item", "s02.startup", persist_kind="startup_entry")
    return s.events


def s09() -> list[Event]:
    """Package installed from the official index: a trusted source, so no label."""
    installer = actor("p-400", "package_installer", "bob", parent="p-399", interactive=True)
    s = Stream(ENDPOINT)
    s.add(
        0,
        "net_connect",
        installer,
        "network_endpoint",
        "s09.index",
        destination_class="package_index",
    )
    s.add(
        500,
        "content_in",
        installer,
        "package_archive",
        "s09.archive",
        source_class="download",
        trusted_source="official-python-index",
    )
    s.add(300, "file_write", installer, "package_files", "s09.files", path_group="site_packages")
    return s.events


def s10() -> list[Event]:
    """An admin runs their own local script."""
    shell = actor("p-500", "interactive_shell", "admin1", parent="p-499", interactive=True)
    script = actor("p-501", "script_host", "admin1", parent="p-500")
    s = Stream(ENDPOINT)
    s.add(0, "admin_input", shell, "script_file", "s10.script", source_class="internal")
    s.add(250, "exec", shell, "command_text", "s10.script", source_class="internal")
    s.add(600, "file_write", script, "report_file", "s10.report", path_group="user_home")
    return s.events


def s11() -> list[Event]:
    """A developer copies a command from a web doc, runs it in a terminal; the effect is local."""
    browser = actor("p-600", "browser", "dev1", interactive=True)
    shell = actor("p-601", "interactive_shell", "dev1", parent="p-599", interactive=True)
    build = actor("p-602", "other", "dev1", parent="p-601")
    s = Stream(ENDPOINT)
    s.add(
        0,
        "content_in",
        browser,
        "web_page",
        "s11.page",
        source_class="web",
    )
    s.add(
        1100,
        "content_in",
        browser,
        "clipboard_text",
        "s11.clipboard",
        source_class="web",
    )
    s.add(9000, "user_input", shell, "command_text", "s11.clipboard", input_method="paste")
    s.add(300, "exec", shell, "command_text", "s11.clipboard")
    s.add(900, "file_write", build, "project_file", "s11.output", path_group="project_dir")
    return s.events


def s13() -> list[Event]:
    """Inbound request makes a web worker spawn a shell, which connects to an unknown host.
    Stand-in only: the 'shell' is an ordinary process in a lab, nothing is exploited."""
    worker = actor("p-1842", "web_worker", "svc-www", parent="p-77")
    shell = actor("p-1843", "script_host", "svc-www", parent="p-1842")
    s = Stream(SERVER)
    s.add(0, "request_in", worker, "request_body", "s13.request", source_class="inbound_request")
    s.add(120, "exec", worker, "command_text", "s13.command", source_class="inbound_request")
    s.add(
        400,
        "net_connect",
        shell,
        "network_endpoint",
        "s13.dest",
        destination_class="unknown",
    )
    s.add(300, "request_end", worker, "request_body", "s13.request")
    return s.events


def s14() -> list[Event]:
    """Inbound request makes a web worker write a new executable script into the web root
    (web shell stand-in; the file is an inert placeholder)."""
    worker = actor("p-1842", "web_worker", "svc-www", parent="p-77")
    s = Stream(SERVER)
    s.add(0, "request_in", worker, "request_body", "s14.request", source_class="inbound_request")
    s.add(
        180,
        "file_write",
        worker,
        "script_file",
        "s14.webshell",
        web_root="main_site",
        executable=True,
        new_file=True,
    )
    s.add(250, "request_end", worker, "request_body", "s14.request")
    return s.events


SCENARIOS: dict[str, Callable[[], list[Event]]] = {
    "S01": s01,
    "S02": s02,
    "S09": s09,
    "S10": s10,
    "S11": s11,
    "S13": s13,
    "S14": s14,
}


def all_scenarios() -> list[str]:
    return sorted({*SCENARIOS, *golden_more.SCENARIOS})


def render(scenario: str) -> str:
    if scenario in golden_more.SCENARIOS:
        events = golden_more.SCENARIOS[scenario]()[0]
    else:
        events = SCENARIOS[scenario]()
    return "".join(event.to_json_line() + "\n" for event in events)


def render_expected(scenario: str) -> str | None:
    """Expected-verdict text for the generated scenarios; S01-S14 keep their hand-written files."""
    if scenario not in golden_more.META:
        return None
    return json.dumps(golden_more.expected(scenario), indent=2) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for scenario in all_scenarios():
        files = {GOLDEN_DIR / f"{scenario}.events.jsonl": render(scenario)}
        if (expected := render_expected(scenario)) is not None:
            files[GOLDEN_DIR / f"{scenario}.expected.json"] = expected
        for path, text in files.items():
            if check:
                if not path.exists() or path.read_text() != text:
                    stale.append(path.name)
            else:
                GOLDEN_DIR.mkdir(exist_ok=True)
                path.write_text(text)
    if stale:
        print("out of date:", ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
