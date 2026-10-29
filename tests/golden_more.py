"""Golden scenarios beyond S01-S14 (CLAUDE.md C8). Every stream is a harmless stand-in.

Each scenario function returns (events, labeled, roots): the processes that carry a label and the
topmost of them. Expected verdicts live in META, written from C8/C13 and the design decisions, never
read back from the pipeline. Expected containment is derived from the declared labeled processes by
`derive_actions`, a few lines that do not use pipeline code.
"""

from golden_dsl import ENDPOINT, SERVER, Stream, actor
from refmon.schemas import Event

Result = tuple[list[Event], list[str], list[str]]


def _lure(s, sid, via="web", clip_via=None, who=None):
    b = who or actor("p-100", "browser", "alice", interactive=True)
    s.add(0, "content_in", b, "web_page", f"{sid}.page", source_class=via)
    s.add(900, "content_in", b, "clipboard_text", f"{sid}.clipboard", source_class=clip_via or via)


# -- pasted and typed commands (ClickFix family) ---------------------------------------------------


def s03() -> Result:
    fm = actor("p-310", "launcher", "alice", interactive=True)
    sh = actor("p-311", "interactive_shell", "alice", parent="p-310")
    sc = actor("p-312", "script_host", "alice", parent="p-311")
    s = Stream(ENDPOINT)
    _lure(s, "s03")
    s.add(5000, "user_input", fm, "command_text", "s03.clipboard", input_method="paste")
    s.add(300, "exec", fm, "command_text", "s03.clipboard", launched_via="file_manager")
    s.add(400, "exec", sh, "command_text", "s03.inner", hidden_window=True, encoded_payload=True)
    s.add(800, "net_connect", sc, "network_endpoint", "s03.dest", destination_class="unknown")
    s.add(
        1500,
        "file_write",
        sc,
        "executable_file",
        "s03.dropped",
        path_group="temp_dir",
        executable=True,
        new_file=True,
    )
    return s.events, ["p-311", "p-312"], ["p-311"]


def s04() -> Result:
    pdf = actor("p-410", "browser", "alice", interactive=True)
    sh = actor("p-411", "interactive_shell", "alice", parent="p-400", interactive=True)
    sc = actor("p-412", "script_host", "alice", parent="p-411")
    s = Stream(ENDPOINT)
    s.add(0, "content_in", pdf, "pdf_file", "s04.pdf", source_class="download")
    s.add(1500, "content_in", pdf, "clipboard_text", "s04.clipboard", source_class="download")
    s.add(6000, "user_input", sh, "command_text", "s04.clipboard", input_method="paste")
    s.add(300, "exec", sh, "command_text", "s04.clipboard", encoded_payload=True)
    s.add(700, "net_connect", sc, "network_endpoint", "s04.dest", destination_class="unknown")
    s.add(
        1200,
        "file_write",
        sc,
        "executable_file",
        "s04.dropped",
        path_group="temp_dir",
        executable=True,
        new_file=True,
    )
    return s.events, ["p-412"], ["p-412"]


def s05() -> Result:
    sh = actor("p-501", "interactive_shell", "alice", parent="p-499", interactive=True)
    sc = actor("p-502", "script_host", "alice", parent="p-501")
    s = Stream(ENDPOINT)
    s.add(0, "user_input", sh, "command_text", "s05.typed", input_method="typed")
    s.add(2500, "exec", sh, "command_text", "s05.typed", hidden_window=True)
    s.add(800, "net_connect", sc, "network_endpoint", "s05.dest", destination_class="unknown")
    # no labeled process: v1.1 (A47) pauses the processes that produced the signals (the shell hid
    # the command, its script host connected out); the shell is their root
    return s.events, [], ["p-501"]


def s06() -> Result:
    sh = actor("p-601", "interactive_shell", "alice", parent="p-599", interactive=True)
    sc = actor("p-602", "script_host", "alice", parent="p-601")
    startup = actor("p-9001", "scheduler", "alice", parent="p-1")
    later = actor("p-9002", "script_host", "alice", parent="p-9001")
    s = Stream(ENDPOINT)
    _lure(s, "s06")
    s.add(5000, "user_input", sh, "command_text", "s06.clipboard", input_method="paste")
    s.add(300, "exec", sh, "command_text", "s06.clipboard")
    s.add(600, "persist", sc, "startup_item", "s06.startup", persist_kind="scheduled_task")
    # a day later the persisted item runs; the label is persistent and carries its Contract evidence
    s.add(86_400_000, "exec", startup, "startup_item", "s06.startup")
    s.add(500, "net_connect", later, "network_endpoint", "s06.dest", destination_class="unknown")
    s.add(
        900,
        "file_write",
        later,
        "executable_file",
        "s06.payload",
        path_group="temp_dir",
        executable=True,
        new_file=True,
    )
    return s.events, ["p-602", "p-9002"], ["p-602", "p-9002"]


def s07() -> Result:
    sh = actor("p-701", "interactive_shell", "alice", parent="p-700", interactive=True)
    sc = actor("p-702", "script_host", "alice", parent="p-701")
    s = Stream(ENDPOINT)
    _lure(s, "s07")
    s.add(5000, "user_input", sh, "command_text", "s07.clipboard", input_method="paste")
    s.add(300, "exec", sh, "command_text", "s07.clipboard")
    s.add(
        700, "net_connect", sc, "network_endpoint", "s07.dest", destination_class="unknown"
    )  # popular file-sharing host
    s.add(
        1200,
        "file_write",
        sc,
        "executable_file",
        "s07.dropped",
        path_group="temp_dir",
        executable=True,
        new_file=True,
    )
    return s.events, ["p-702"], ["p-702"]


def s08() -> Result:
    sh = actor("p-801", "interactive_shell", "alice", parent="p-800", interactive=True)
    sc = actor("p-802", "script_host", "alice", parent="p-801")
    s = Stream(ENDPOINT)
    _lure(s, "s08")
    s.add(5000, "user_input", sh, "command_text", "s08.clipboard", input_method="paste")
    s.add(300, "exec", sh, "command_text", "s08.clipboard")
    s.add(900, "asset_access", sc, "credential_store", "s08.decoy", canary_hit=True)
    return s.events, ["p-802"], ["p-802"]


def s12() -> Result:
    ag = actor("p-1200", "agent", "svc-agent", parent="p-1")
    ch = actor("p-1201", "script_host", "svc-agent", parent="p-1200")
    s = Stream(ENDPOINT)
    s.add(0, "content_in", ag, "web_page", "s12.page", source_class="agent_input")
    s.add(1500, "exec", ag, "command_text", "s12.cmd", exec_class="unknown", encoded_payload=True)
    s.add(700, "net_connect", ch, "network_endpoint", "s12.dest", destination_class="unknown")
    return s.events, ["p-1200", "p-1201"], ["p-1200"]


# -- server scenarios -------------------------------------------------------------------------------


def _worker(pid="p-1500", role="web_worker"):
    return actor(pid, role, "svc-www", parent="p-77")


def s15() -> Result:
    w = _worker("p-1500")
    s = Stream(SERVER)
    s.add(0, "request_in", w, "request_body", "s15.request", source_class="inbound_request")
    s.add(200, "net_connect", w, "network_endpoint", "s15.dest", destination_class="unknown")
    s.add(300, "request_end", w, "request_body", "s15.request")
    return s.events, ["p-1500"], ["p-1500"]


def s17() -> Result:
    w = _worker("p-1700", "app_server")
    s = Stream(SERVER)
    s.add(0, "request_in", w, "request_body", "s17.request", source_class="inbound_request")
    s.add(250, "priv_change", w, "privilege_level", "s17.root")
    return s.events, ["p-1700"], ["p-1700"]


def s18() -> Result:
    w = _worker("p-1800")
    sc = actor("p-1801", "script_host", "svc-www", parent="p-1800")
    s = Stream(SERVER)
    s.add(
        0, "request_in", w, "request_body", "s18.request", source_class="inbound_request"
    )  # initial access
    for i in range(30):
        s.add(
            100,
            "net_connect",
            sc,
            "network_endpoint",
            f"s18.h{i}",
            destination_class="internal_network",
        )
    return s.events, ["p-1800", "p-1801"], ["p-1800"]


def s19() -> Result:
    w = _worker("p-1900")
    sc = actor("p-1901", "script_host", "svc-www", parent="p-1900")
    s = Stream(SERVER)
    s.add(
        0, "request_in", w, "request_body", "s19.request", source_class="inbound_request"
    )  # initial access
    for i in range(55):
        s.add(50, "file_write", sc, "user_file", f"s19.f{i}", path_group="user_home")
    return s.events, ["p-1900", "p-1901"], ["p-1900"]


def s20() -> Result:
    w = _worker("p-2000")
    sc = actor("p-2001", "script_host", "svc-www", parent="p-2000")
    s = Stream(SERVER)
    s.add(
        0, "request_in", w, "request_body", "s20.request", source_class="inbound_request"
    )  # initial access
    s.add(300, "security_tamper", sc, "security_tool", "s20.av")
    s.add(300, "security_tamper", sc, "log_store", "s20.logs")
    return s.events, ["p-2000", "p-2001"], ["p-2000"]


def s21() -> Result:
    inst = actor("p-2100", "package_installer", "bob", parent="p-2099", interactive=True)
    sc = actor("p-2101", "script_host", "bob", parent="p-2100")
    s = Stream(ENDPOINT)
    s.add(
        0, "content_in", inst, "package_archive", "s21.archive", source_class="package"
    )  # unlisted mirror
    s.add(500, "exec", inst, "command_text", "s21.setup")
    s.add(600, "asset_access", sc, "credential_store", "s21.creds")
    s.add(700, "persist", inst, "startup_item", "s21.startup", persist_kind="startup_entry")
    return s.events, ["p-2100", "p-2101"], ["p-2100"]


def s22() -> Result:
    w = _worker("p-2200")
    s = Stream(SERVER)
    s.add(0, "request_in", w, "request_body", "s22.request", source_class="inbound_request")
    s.add(
        400,
        "net_connect",
        w,
        "network_endpoint",
        "s22.db",
        destination_class="db_server",
        bytes=800_000_000,
    )
    s.add(300, "request_end", w, "request_body", "s22.request")
    return s.events, ["p-2200"], ["p-2200"]


def s23() -> Result:
    w = _worker("p-2300")
    s = Stream(SERVER)
    s.add(0, "request_in", w, "request_body", "s23.request", source_class="inbound_request")
    s.add(100, "file_write", w, "cache_file", "s23.cache", path_group="cache")
    s.add(100, "file_write", w, "session_file", "s23.session", path_group="sessions")
    s.add(200, "request_end", w, "request_body", "s23.request")
    return s.events, ["p-2300"], ["p-2300"]


def s24() -> Result:
    dt = actor("p-2400", "deploy_tool", "admin1", parent="p-2399", interactive=True)
    s = Stream(SERVER)
    s.add(
        0,
        "content_in",
        dt,
        "site_release",
        "s24.release",
        source_class="download",
        trusted_source="deploy-artifacts",
    )
    s.add(
        500,
        "file_write",
        dt,
        "script_file",
        "s24.page",
        web_root="main_site",
        executable=True,
        new_file=True,
    )
    return s.events, [], []


def s25() -> Result:
    n = _worker("p-2500", "node_app_server")
    ch = actor("p-2501", "script_host", "svc-www", parent="p-2500")
    s = Stream(SERVER)
    s.add(0, "request_in", n, "request_body", "s25.request", source_class="inbound_request")
    s.add(150, "exec", n, "command_text", "s25.command")  # the child process (stand-in)
    s.add(400, "net_connect", ch, "network_endpoint", "s25.dest", destination_class="unknown")
    s.add(300, "request_end", n, "request_body", "s25.request")
    return s.events, ["p-2500", "p-2501"], ["p-2500"]


def _node_fetch(sid):
    n = _worker("p-2600", "node_app_server")
    s = Stream(SERVER)
    s.add(0, "net_connect", n, "network_endpoint", f"{sid}.api", destination_class="partner_api")
    s.add(300, "content_in", n, "api_response", f"{sid}.response", source_class="outbound_response")
    return s, n


def s26a() -> Result:
    s, n = _node_fetch("s26a")
    s.add(400, "file_write", n, "cache_file", "s26a.cache", path_group="fetch_cache", new_file=True)
    return s.events, ["p-2600"], ["p-2600"]


def s26b() -> Result:
    s, n = _node_fetch("s26b")
    s.add(400, "net_connect", n, "network_endpoint", "s26b.dest", destination_class="unknown")
    return s.events, ["p-2600"], ["p-2600"]


def s26c() -> Result:
    s, n = _node_fetch("s26c")
    s.add(
        400,
        "file_write",
        n,
        "script_file",
        "s26c.page",
        web_root="main_site",
        executable=True,
        new_file=True,
    )
    return s.events, ["p-2600"], ["p-2600"]


def s27() -> Result:
    w = _worker("p-2700")
    s = Stream(SERVER)
    s.add(0, "request_in", w, "request_body", "s27.request", source_class="inbound_request")
    for _ in range(3):
        s.add(1000, "response_out", w, "client", "s27.client", bytes=20_000_000)
    return s.events, ["p-2700"], ["p-2700"]


def s30() -> Result:
    n = _worker("p-3000", "node_app_server")
    ch = actor("p-3001", "other", "svc-www", parent="p-3000")
    s = Stream(SERVER)
    s.add(0, "request_in", n, "request_body", "s30.request", source_class="inbound_request")
    s.add(200, "exec", n, "command_text", "s30.build", exec_class="build_tool")
    s.add(400, "file_write", ch, "build_output", "s30.output", path_group="app_data")
    s.add(300, "request_end", n, "request_body", "s30.request")
    return s.events, ["p-3000", "p-3001"], ["p-3000"]


# -- endpoint families beyond pasted commands ------------------------------------------------------


def s31() -> Result:
    mail = actor("p-3100", "mail", "carol", interactive=True)
    off = actor("p-3101", "office", "carol", parent="p-3099", interactive=True)
    sc = actor("p-3102", "script_host", "carol", parent="p-3101")
    s = Stream(ENDPOINT)
    s.add(0, "content_in", mail, "attachment", "s31.doc", source_class="mail")
    s.add(4000, "content_in", off, "attachment", "s31.doc", source_class="mail")
    s.add(900, "exec", off, "command_text", "s31.macro", exec_class="unknown")
    s.add(600, "net_connect", sc, "network_endpoint", "s31.dest", destination_class="unknown")
    s.add(500, "persist", sc, "startup_item", "s31.startup", persist_kind="startup_entry")
    return s.events, ["p-3101", "p-3102"], ["p-3101"]


def _file_launch(sid, source, pid, child_role="other"):
    br = actor("p-100", "browser", "alice", interactive=True)
    ln = actor(f"p-{pid}", "launcher", "alice", interactive=True)
    ch = actor(f"p-{pid + 1}", child_role, "alice", parent=f"p-{pid}")
    s = Stream(ENDPOINT)
    if source == "removable":
        s.add(0, "content_in", ln, "executable_file", f"{sid}.program", source_class="removable")
    else:
        s.add(0, "content_in", br, "executable_file", f"{sid}.program", source_class=source)
    return s, ln, ch


def s32() -> Result:
    s, ln, ch = _file_launch("s32", "removable", 3200)
    s.add(4000, "exec", ln, "executable_file", "s32.program", signed=False)
    s.add(600, "net_connect", ch, "network_endpoint", "s32.dest", destination_class="unknown")
    s.add(500, "persist", ch, "startup_item", "s32.startup", persist_kind="startup_entry")
    return s.events, ["p-3201"], ["p-3201"]


def s33() -> Result:
    s, ln, ch = _file_launch("s33", "download", 3300)
    s.add(4000, "exec", ln, "executable_file", "s33.program", signed=False)
    s.add(400, "exec", ch, "command_text", "s33.inner", hidden_window=True)
    s.add(600, "net_connect", ch, "network_endpoint", "s33.dest", destination_class="unknown")
    s.add(500, "persist", ch, "startup_item", "s33.startup", persist_kind="startup_entry")
    return s.events, ["p-3301"], ["p-3301"]


def s34() -> Result:
    s, ln, ch = _file_launch("s34", "download", 3400)
    s.add(4000, "exec", ln, "executable_file", "s34.program", signed=False)
    s.add(
        700,
        "asset_access",
        ch,
        "credential_store",
        "s34.browser_store",
        protected_asset="browser-passwords",
    )
    return s.events, ["p-3401"], ["p-3401"]


def s35() -> Result:
    s, ln, ch = _file_launch("s35", "web", 3500, "script_host")
    s.add(4000, "exec", ln, "script_file", "s35.program", signed=False)
    s.add(300, "exec", ch, "command_text", "s35.inner", hidden_window=True)
    s.add(600, "net_connect", ch, "network_endpoint", "s35.dest", destination_class="unknown")
    return s.events, ["p-3501"], ["p-3501"]


def s36() -> Result:
    mail = actor("p-3600", "mail", "dana", interactive=True)
    off = actor("p-3601", "office", "dana", parent="p-3599", interactive=True)
    s = Stream(ENDPOINT)
    s.add(0, "content_in", mail, "attachment", "s36.pdf", source_class="mail")
    s.add(3000, "content_in", off, "attachment", "s36.pdf", source_class="mail")
    s.add(5000, "exec", off, "command_text", "s36.print", exec_class="print_helper")
    return s.events, ["p-3601"], ["p-3601"]


def s37() -> Result:
    inst = actor("p-3700", "package_installer", "it-admin", parent="p-3699", interactive=True)
    s = Stream(ENDPOINT)
    s.add(
        0,
        "content_in",
        inst,
        "package_archive",
        "s37.archive",
        source_class="download",
        trusted_source="university-software-portal",
    )
    s.add(700, "persist", inst, "startup_item", "s37.service", persist_kind="startup_entry")
    return s.events, [], []


def s38() -> Result:
    off = actor("p-3800", "office", "erin", parent="p-3799", interactive=True)
    s = Stream(ENDPOINT)
    s.add(0, "content_in", off, "document", "s38.doc", source_class="removable")
    s.add(3000, "exec", off, "command_text", "s38.print", exec_class="print_helper")
    return s.events, ["p-3800"], ["p-3800"]


def s39() -> Result:
    br = actor("p-3900", "browser", "frank", interactive=True)
    s = Stream(ENDPOINT)
    s.add(
        0, "asset_access", br, "credential_store", "s39.store", protected_asset="browser-passwords"
    )
    return s.events, [], []


def s40() -> Result:
    sh = actor("p-4000", "interactive_shell", "admin1", parent="p-3999", interactive=True)
    tool = actor("p-4001", "elevation_tool", "admin1", parent="p-4000")
    s = Stream(ENDPOINT)
    s.add(0, "admin_input", sh, "command_text", "s40.cmd", source_class="internal")
    s.add(300, "priv_change", tool, "privilege_level", "s40.elevated")
    return s.events, [], []


def s44() -> Result:
    bk = actor("p-4400", "backup_job", "svc-backup", parent="p-1")
    s = Stream(SERVER)
    s.add(
        0,
        "net_connect",
        bk,
        "network_endpoint",
        "s44.backup",
        destination_class="backup_host",
        bytes=60_000_000_000,
    )
    return s.events, [], []


def s45() -> Result:
    ag = actor("p-4500", "agent", "svc-agent", parent="p-1")
    s = Stream(ENDPOINT)
    s.add(0, "exec", ag, "command_text", "s45.cmd", exec_class="agent_tools")
    return s.events, [], []


def s46() -> Result:
    bk = actor("p-4600", "backup_job", "svc-backup", parent="p-1")
    s = Stream(SERVER)
    for i in range(55):
        s.add(50, "file_write", bk, "backup_file", f"s46.f{i}", path_group="backup_target")
    return s.events, [], []


def s47() -> Result:
    sc = actor("p-4700", "vuln_scanner", "secops", parent="p-1")
    s = Stream(SERVER)
    for i in range(30):
        s.add(
            100,
            "net_connect",
            sc,
            "network_endpoint",
            f"s47.h{i}",
            destination_class="internal_network",
        )
    return s.events, [], []


def s48() -> Result:
    pt = actor("p-4800", "patch_tool", "svc-patch", parent="p-1")
    s = Stream(SERVER)
    s.add(0, "security_tamper", pt, "service", "s48.svc")
    s.add(300, "security_tamper", pt, "security_tool", "s48.av")
    return s.events, [], []


def s49() -> Result:
    s, ln, ch = _file_launch("s49", "download", 4900)
    s.add(4000, "exec", ln, "executable_file", "s49.program", signed=True)
    s.add(900, "persist", ch, "startup_item", "s49.service", persist_kind="startup_entry")
    return s.events, ["p-4901"], ["p-4901"]


def s50() -> Result:
    bk = actor("p-5000", "backup_job", "svc-backup", parent="p-1")
    s = Stream(SERVER)
    s.add(0, "content_in", bk, "job_ticket", "s50.ticket", source_class="download")
    for i in range(55):
        s.add(50, "file_write", bk, "backup_file", f"s50.f{i}", path_group="backup_target")
    return s.events, ["p-5000"], ["p-5000"]


SCENARIOS = {
    "S03": s03, "S04": s04, "S05": s05, "S06": s06, "S07": s07, "S08": s08, "S12": s12, "S15": s15,
    "S17": s17, "S18": s18, "S19": s19, "S20": s20, "S21": s21, "S22": s22, "S23": s23, "S24": s24,
    "S25": s25, "S26a": s26a, "S26b": s26b, "S26c": s26c, "S27": s27, "S30": s30, "S31": s31,
    "S32": s32, "S33": s33, "S34": s34, "S35": s35, "S36": s36, "S37": s37, "S38": s38, "S39": s39,
    "S40": s40, "S44": s44, "S45": s45, "S46": s46, "S47": s47, "S48": s48, "S49": s49, "S50": s50,
}  # fmt: skip

ORIGIN, C, E = "origin", "contract", "effect"


def _m(
    title,
    kind,
    platform,
    decision,
    questions=(),
    effects=(),
    *,
    rule=None,
    phase="1",
    override=None,
    gap=False,
    notes="",
):
    return {
        "title": title, "kind": kind, "platform": platform, "decision": decision,
        "rule_decision": rule or decision, "decided_in_phase": phase, "questions_failed": list(questions),
        "effects": list(effects), "override": override, "known_gap": gap, "notes": notes,
    }  # fmt: skip


META = {
    "S03": _m("Command pasted into file manager address bar", "malicious", "endpoint", "block", [ORIGIN, C, E], ["hide", "fetch"]),
    "S04": _m("Command copied from PDF, pasted", "malicious", "endpoint", "block", [ORIGIN, C, E], ["hide", "fetch"]),
    "S05": _m("Command typed by hand from a video", "malicious", "endpoint", "hold", [E], ["hide", "fetch"], rule="allow", phase="4b", gap=True,
              notes="Known gap. No label, so Origin and the external-exec contract cannot fire; only Effect does. The fail rule allows it; the evidence calculus (effect 2.5 alone, L -4.41) holds it."),
    "S06": _m("Persistence now, payload runs a day later", "malicious", "endpoint", "block", [ORIGIN, C, E], ["persist", "fetch"],
              notes="The delayed run is a new story. Its Contract signal comes from the persistent label of the startup item (contract evidence, D21)."),
    "S07": _m("Payload on popular file-sharing host", "malicious", "endpoint", "block", [ORIGIN, C, E], ["fetch"]),
    "S08": _m("Labeled process reads canary credential", "malicious", "endpoint", "block", [ORIGIN, C, E], ["credential"], override="canary"),
    "S12": _m("AI agent runs command from injected web content", "malicious", "endpoint", "block", [ORIGIN, C, E], ["fetch", "hide"]),
    "S15": _m("Web worker connects to unknown internet host", "malicious", "server", "block", [ORIGIN, C, E], ["fetch"]),
    "S17": _m("Service process gains elevated privileges (story includes an initial-access label)", "malicious", "server", "block", [ORIGIN, C, E], ["escalate"]),
    "S18": _m("Compromised host opens new connections to many internal hosts (story includes an initial-access label)", "malicious", "server", "block", [ORIGIN, C, E], ["fetch", "lateral"]),
    "S19": _m("Process changes many files rapidly (ransomware stand-in; story includes an initial-access label)", "malicious", "server", "block", [ORIGIN, C, E], ["mass_change"]),
    "S20": _m("Process stops security tool or clears logs (story includes an initial-access label)", "malicious", "server", "block", [ORIGIN, C, E], ["tamper"]),
    "S21": _m("Package install script reads credentials or persists", "malicious", "endpoint", "block", [ORIGIN, C, E], ["credential", "persist"],
              notes="The package comes from an unlisted mirror, not the trusted official index; a trusted source is an absolute allow."),
    "S22": _m("Attacker abuses app's own allowed DB connection to read data", "malicious", "server", "hold", [ORIGIN, E], ["exfil"], gap=True,
              notes="Known gap: no contract is broken, only the transferred volume stands out."),
    "S23": _m("Web worker writes normal cache and session files", "benign", "server", "allow", [ORIGIN], []),
    "S24": _m("Admin deploys new site version via deployment tool", "benign", "server", "allow", [E], ["persist"], override="trusted_root"),
    "S25": _m("Inbound request with malformed compressed body: Node app server spawns a child process", "malicious", "server", "block", [ORIGIN, C, E], ["fetch"]),
    "S26a": _m("Node app server fetches an external URL, response leads to a non-executable file write (cache)", "benign", "server", "allow", [ORIGIN, C], [], rule="hold", phase="4b",
               notes="Two questions fail, so the plain rule says hold; the evidence calculus (origin 0.8 + contract 1.0, L -5.11) allows it, as C8 expects (design decision D1)."),
    "S26b": _m("Node app server fetches an external URL, response triggers an unexpected outbound connection", "malicious", "server", "block", [ORIGIN, C, E], ["fetch"]),
    "S26c": _m("Node app server fetches an external URL, response triggers an executable file write", "malicious", "server", "block", [ORIGIN, C, E], ["persist"]),
    "S27": _m("Server returns oversized responses to one client (memory-leak stage stand-in)", "malicious", "server", "block", [ORIGIN, C, E], ["response_anomaly"],
              notes="Hold at the first oversized response; the repeat to the same client turns it into a block."),
    "S30": _m("Node app server legitimately runs an approved build tool child process", "benign", "server", "allow", [ORIGIN], []),
    "S31": _m("Document from a mail attachment makes the office app start a script host (macro stand-in)", "malicious", "endpoint", "block", [ORIGIN, C, E], ["fetch", "persist"]),
    "S32": _m("Program launched from removable media connects out and creates a startup entry", "malicious", "endpoint", "block", [ORIGIN, C, E], ["fetch", "persist"]),
    "S33": _m("Downloaded fake installer runs, persists and contacts an unknown host", "malicious", "endpoint", "block", [ORIGIN, C, E], ["hide", "fetch", "persist"]),
    "S34": _m("Labeled process reads the real browser credential store (infostealer stand-in)", "malicious", "endpoint", "block", [ORIGIN, C, E], ["credential", "asset_access"], override="protected_asset"),
    "S35": _m("User opens a file downloaded from a link, it starts a hidden script that fetches more code", "malicious", "endpoint", "block", [ORIGIN, C, E], ["hide", "fetch"]),
    "S36": _m("User opens a normal PDF from a mail attachment and prints it", "benign", "endpoint", "allow", [ORIGIN], []),
    "S37": _m("IT installs signed software from the university software portal", "benign", "endpoint", "allow", [C, E], ["persist"], override="trusted_root",
              notes="Contract and Effect both fail (the installer persists), yet a trusted source is an absolute allow."),
    "S38": _m("User opens and prints a normal document from a removable medium", "benign", "endpoint", "allow", [ORIGIN], []),
    "S39": _m("Browser reads its own password store (its contract allows it)", "benign", "endpoint", "allow", [], []),
    "S40": _m("Admin elevates privileges with an approved elevation tool (its contract allows it)", "benign", "endpoint", "allow", [], []),
    "S44": _m("Nightly backup sends a large volume to the known backup host", "benign", "server", "allow", [], []),
    "S45": _m("AI agent runs a command from its allowlist (no external input)", "benign", "endpoint", "allow", [], []),
    "S46": _m("Backup job (contract allows mass change) changes many files (no external origin label)", "benign", "server", "allow", [], []),
    "S47": _m("Admin vulnerability scanner (contract allows fan-out) connects to many internal hosts", "benign", "server", "allow", [], []),
    "S48": _m("Patch tool (contract allows tampering) stops services, among them a security service", "benign", "server", "allow", [], []),
    "S49": _m("Signed vendor installer downloaded from the internet persists (role other, no contract)", "benign", "endpoint", "hold", [ORIGIN, E], ["persist"]),
    "S50": _m("Backup job (contract allows mass change) changes many files in a story with an external origin label", "benign", "server", "hold", [ORIGIN, E], ["mass_change"]),
}  # fmt: skip


def derive_actions(events, labeled, roots, decision, effects, device):
    """Containment the Phase 3 rules prescribe, from the declared labeled processes only."""
    if decision == "hold":
        return [{"type": "hold", "process": r} for r in roots]
    if decision != "block":
        return []
    acts = [{"type": "kill_process_tree", "process": r} for r in roots]
    cut = [p for p in labeled if any(e.actor.id == p and e.type == "net_connect" for e in events)]
    acts += [{"type": "cut_network", "process": p} for p in cut]
    for e in events:
        if e.actor.id not in labeled:
            continue
        if e.type == "file_write":
            kind = "quarantine_file" if e.attrs.get("new_file") else "restore_file"
            acts.append({"type": kind, "object_of_event": e.event_id})
        elif e.type == "persist":
            acts.append({"type": "revert_persistence", "object_of_event": e.event_id})
    if "lateral" in effects:
        acts.append({"type": "isolate_host", "host": device})
    return acts


def expected(scenario):
    events, labeled, roots = SCENARIOS[scenario]()
    m = dict(META[scenario])
    m["scenario"] = scenario
    device = events[0].device
    m["actions"] = derive_actions(events, labeled, roots, m["decision"], m["effects"], device)
    return {k: v for k, v in m.items() if v not in (None, "", [])} | {"scenario": scenario}
