"""Observe: the only stage that sees raw content (CLAUDE.md C2, Part A privacy constraint).

It turns a RawEvent into an Event: content becomes an HMAC-SHA256 fingerprint under the device key,
and everything that needs a raw domain, host, IP, URL path or program name is decided here and
only its outcome is emitted. Nothing raw leaves this module. Already-observed Events pass through.
A sensor cannot set the outcome attributes itself; those keys are overwritten.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections import deque
from datetime import timedelta

from ..calculus.privacy import BloomFilter
from ..policy import Policy
from ..schemas import EVENT_ATTR_KEYS, Event, EventType, ObjectRef, RawEvent
from .features import obfuscation_features

EXTERNAL_SOURCES = {
    "web",
    "mail",
    "removable",
    "download",
    "inbound_request",
    "outbound_response",
    "package",
    "agent_input",
}

# Attribute keys decided by Observe from raw data and policy. Whatever a sensor sends under these
# names is discarded, so a sensor cannot claim a trusted source or hide a threat-list hit.
OBSERVE_OWNED = {
    "trusted_source",
    "destination_class",
    "exec_class",
    "protected_asset",
    "threat_list_hit",
    "canary_hit",
}

# Events whose content is text that can be obfuscated (a command, pasted or fetched content).
FEATURE_EVENTS = {
    EventType.EXEC,
    EventType.CONTENT_IN,
    EventType.USER_INPUT,
    EventType.ADMIN_INPUT,
}

_THREAT_KEY = b"refmon-threat-list-digest"  # list-keyed digest, never emitted (design decision D7)


def normalize(text: str) -> str:
    return " ".join(text.split())


class ThreatLists:
    """Threat lists held as list-keyed digests. A Bloom filter (sized for the policy false-positive
    rate, C11.8) answers first; a hit is only a hint and is confirmed against the exact list before
    it is reported, so a false positive of the filter never becomes a `threat_list_hit`."""

    def __init__(self, policy: Policy) -> None:
        self._lists: dict[str, tuple[str, set[str], BloomFilter]] = {}
        for spec in policy.threat_lists:
            exact = {self.digest(e) for e in spec.entries}
            bloom = BloomFilter(len(exact), policy.math.bloom_fp_rate)
            for digest in exact:
                bloom.add(digest)
            self._lists[spec.name] = (spec.kind, exact, bloom)
        self.bloom_hints = 0  # filter hits, confirmed or not
        self.bloom_false_hints = 0  # filter hits the exact list rejected

    @staticmethod
    def digest(value: str) -> str:
        return hmac.new(_THREAT_KEY, normalize(value).lower().encode(), hashlib.sha256).hexdigest()

    def hit(self, kind: str, values: list[str]) -> str | None:
        wanted = {self.digest(v) for v in values if v}
        for name, (list_kind, exact, bloom) in self._lists.items():
            if list_kind != kind:
                continue
            for digest in wanted:
                if not bloom.might_contain(digest):
                    continue
                self.bloom_hints += 1
                if digest in exact:  # confirmed against the exact list
                    return name
                self.bloom_false_hints += 1
        return None


class Observe:
    def __init__(self, policy: Policy, key: bytes, *, features=None) -> None:
        if not key:
            raise ValueError("Observe needs a per-device key")
        self.policy = policy
        self._key = key
        self.threat_lists = ThreatLists(policy)
        # Obfuscation features (C11.7) are measured here, before the content is dropped.
        self.features = obfuscation_features if features is None else features
        # Ring buffer of observed Events only (never raw content), at most buffer_max_age old.
        self.buffer: deque[Event] = deque()

    def fingerprint(self, content: str) -> str:
        return (
            "hmac:" + hmac.new(self._key, normalize(content).encode(), hashlib.sha256).hexdigest()
        )

    def __call__(self, event: RawEvent | Event) -> Event:
        observed = event if isinstance(event, Event) else self._observe(event)
        self._remember(observed)
        return observed

    # -- internals ---------------------------------------------------------------------------------

    def _remember(self, event: Event) -> None:
        self.buffer.append(event)
        horizon = event.ts - timedelta(seconds=self.policy.thresholds.buffer_max_age)
        while self.buffer and self.buffer[0].ts < horizon:
            self.buffer.popleft()

    def _observe(self, ev: RawEvent) -> Event:
        raw = ev.attrs
        attrs = {k: v for k, v in raw.items() if k in EVENT_ATTR_KEYS and k not in OBSERVE_OWNED}
        content = ev.object.content
        fingerprint = ev.object.fingerprint
        if content is not None:
            fingerprint = self.fingerprint(content)
            if ev.type in FEATURE_EVENTS and self.features is not False:
                attrs.update(self.features(content, self.policy))

        trusted = self._trusted_source(ev)
        if trusted:
            attrs["trusted_source"] = trusted
        if ev.type is EventType.NET_CONNECT:
            attrs["destination_class"] = self._destination_class(raw.get("host"), raw.get("ip"))
        if ev.type is EventType.EXEC:
            attrs["exec_class"] = self._exec_class(raw.get("program"))
        if ev.type is EventType.ASSET_ACCESS:
            asset = self._protected_asset(ev)
            if asset:
                attrs["protected_asset"] = asset
        hit = self._threat_hit(ev)
        if hit is None and fingerprint is not None:  # confirmed block-list entries (Phase 4 Tune)
            hit = self.threat_lists.hit("fingerprint", [fingerprint])
        if hit:
            attrs["threat_list_hit"] = hit
        if self._canary_hit(ev):
            attrs["canary_hit"] = True

        obj = ObjectRef(class_=ev.object.class_, fingerprint=fingerprint)
        return Event(
            event_id=ev.event_id, ts=ev.ts, device=ev.device, type=ev.type, actor=ev.actor,
            object=obj, attrs=attrs,
        )  # fmt: skip

    def _trusted_source(self, ev: RawEvent) -> str | None:
        if ev.type not in (EventType.CONTENT_IN, EventType.REQUEST_IN):
            return None
        raw = ev.attrs
        for source in self.policy.trusted_sources:
            if self._matches(source.match, ev, raw):
                return source.name
        return None

    def _matches(self, match: dict, ev: RawEvent, raw: dict) -> bool:
        facts = {
            "source_class": raw.get("source_class"),
            "domain": raw.get("domain"),
            "signer": raw.get("signer"),
            "actor_role": ev.actor.role,
            "group": self.policy.user_groups.get(ev.actor.user),
        }
        for key, wanted in match.items():
            if key not in facts or facts[key] is None:
                return False
            allowed = wanted if isinstance(wanted, list) else [wanted]
            if facts[key] not in allowed:
                return False
        return bool(match)

    def _destination_class(self, host: str | None, ip: str | None) -> str:
        for dest in self.policy.destinations:
            if host and host.lower() in [h.lower() for h in dest.match.get("host", [])]:
                return dest.name
            if ip:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(
                    addr in ipaddress.ip_network(c, strict=False)
                    for c in dest.match.get("cidr", [])
                ):
                    return dest.name
        return "unknown"

    def _exec_class(self, program: str | None) -> str:
        for exe in self.policy.executables:
            if program and program in exe.match.get("program", []):
                return exe.name
        return "unknown"

    def _protected_asset(self, ev: RawEvent) -> str | None:
        raw = ev.attrs
        for asset in self.policy.protected_assets:
            if asset.class_ == "path_group":
                if asset.value is not None and raw.get("path_group") == asset.value:
                    return asset.name
            elif ev.object.class_ == asset.class_:
                return asset.name
        return None

    def _threat_hit(self, ev: RawEvent) -> str | None:
        raw = ev.attrs
        if ev.type is EventType.NET_CONNECT:
            return self.threat_lists.hit("host", [raw.get("host"), raw.get("domain")])
        if ev.type is EventType.CONTENT_IN:
            hit = self.threat_lists.hit("host", [raw.get("domain")])
            if hit is None and ev.object.content is not None:
                hit = self.threat_lists.hit("content", [ev.object.content])
            return hit
        if ev.type is EventType.REQUEST_IN:
            return self.threat_lists.hit("url", [raw.get("url_path")])
        return None

    def _canary_hit(self, ev: RawEvent) -> bool:
        raw = ev.attrs
        for canary in self.policy.canaries:
            if canary.value is None:
                continue
            if canary.class_ == "url_path" and ev.type is EventType.REQUEST_IN:
                path = raw.get("url_path")
                if isinstance(path, str) and path.startswith(canary.value):
                    return True
            is_credential = canary.class_ == "credential" and ev.type is EventType.ASSET_ACCESS
            content = ev.object.content
            if (
                is_credential
                and content is not None
                and normalize(content) == normalize(canary.value)
            ):
                return True
        return False
