"""The kind of thing an event shows the acting role doing: the unit of a role baseline (C11.3)."""

from .schemas import Event, EventType


def behaviour_kind(ev: Event) -> str:
    """The kind of thing an event shows the acting role doing (the unit of the role baseline)."""
    attrs, typ = ev.attrs, ev.type
    if typ is EventType.EXEC:
        return f"exec:{attrs.get('exec_class', 'unknown')}"
    if typ is EventType.NET_CONNECT:
        return f"connect:{attrs.get('destination_class', 'unknown')}"
    if typ is EventType.FILE_WRITE:
        group = attrs.get("path_group") or attrs.get("web_root") or "none"
        return f"write:{group}" + (":executable" if attrs.get("executable") is True else "")
    if typ is EventType.ASSET_ACCESS:
        return f"asset:{attrs.get('protected_asset') or ev.object.class_}"
    if typ in (EventType.CONTENT_IN, EventType.REQUEST_IN):
        return f"{typ.value}:{attrs.get('source_class', 'unknown')}"
    return typ.value
