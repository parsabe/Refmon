"""Tag: labels and their propagation (CLAUDE.md C3, rules 1 to 7).

1. content_in / request_in from an external source creates a label of strength 1.0.
2. A process that ingests labeled content or a request carries the label until the request ends
   (request_end) or the label decays. Roles that are the channel itself (browser, mail, launcher)
   do not carry labels.
3. An exec whose object fingerprint matches labeled content hands the label to the process it
   spawns.
4. A child process inherits all labels of its parent.
5. Files and persistence items written by a labeled process inherit its labels; persistence items
   and files in web roots are persistent.
6. Strength decays with the half-life unless the label is persistent. Trusted sources create none.
7. A persistent label carries the Contract signals of the story that created it (contract_evidence).
   v1.1 (A49): a label of any kind that has seen Contract signals carries them, and a label that
   carries Contract evidence does not decay (it keeps the strength it had when it got them).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..calculus.labels import attenuate, decay, noisy_or
from ..policy import Policy
from ..schemas import Event, EventType, Label, Origin, SourceClass
from .observe import EXTERNAL_SOURCES


@dataclass
class Tagged:
    event: Event
    actor_labels: tuple[str, ...] = ()
    object_labels: tuple[str, ...] = ()
    new_labels: tuple[str, ...] = ()
    trusted: bool = False
    first_seen: bool = False


@dataclass
class _Proc:
    parent: str | None
    role: str
    labels: set[str] = field(default_factory=set)
    # Every label the process has carried, also after the request that brought it ended. Contain
    # acts on a process that carried a live label: a worker that handled the request which led to a
    # shell is part of the story even once the request is over.
    ever: set[str] = field(default_factory=set)


class Tagger:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.labels: dict[str, Label] = {}
        self.procs: dict[str, _Proc] = {}
        self.fp_labels: dict[str, set[str]] = {}
        self.pending: dict[str, set[str]] = {}  # spawner -> labels for its next new child
        self.requests: dict[tuple[str, str], str] = {}  # (process, request fp) -> label
        self.derived: dict[tuple[str, str], str] = {}  # (parent label, object fp) -> label
        self.written_by: dict[str, str] = {}  # object fp -> process that wrote it
        self._counter = 0

    # -- queries --

    def strength(self, label_id: str, ts) -> float:
        label = self.labels[label_id]
        fixed = label.persistent or bool(label.contract_evidence)
        half_life = None if fixed else self.policy.thresholds.decay_half_life
        return decay(label.strength, (ts - label.created).total_seconds(), half_life)

    def combined(self, label_ids, ts) -> float:
        return noisy_or(self.strength(i, ts) for i in label_ids)

    def alive(self, label_ids, ts) -> tuple[str, ...]:
        floor = self.policy.thresholds.label_alive_floor
        return tuple(sorted(i for i in label_ids if self.strength(i, ts) >= floor))

    def root_of(self, pid: str) -> str:
        seen = set()
        while pid in self.procs and self.procs[pid].parent in self.procs and pid not in seen:
            seen.add(pid)
            pid = self.procs[pid].parent  # type: ignore[assignment]
        return pid

    def descendants(self, pid: str) -> set[str]:
        out = {pid}
        grew = True
        while grew:
            grew = False
            for p, info in self.procs.items():
                if info.parent in out and p not in out:
                    out.add(p)
                    grew = True
        return out

    def set_evidence(self, label_ids, evidence: tuple[str, ...], ts=None) -> None:
        """Attach Contract signals to labels (D21; v1.1: any label, and it stops decaying).

        A label that did not carry evidence and is not persistent is frozen at the strength it has
        at `ts`, so attaching evidence never makes a faded label strong again.
        """
        if not evidence:
            return
        for lid in label_ids:
            label = self.labels[lid]
            update: dict = {
                "contract_evidence": tuple(sorted(set(label.contract_evidence) | set(evidence)))
            }
            if ts is not None and not (label.persistent or label.contract_evidence):
                update["strength"] = min(1.0, self.strength(lid, ts))
            self.labels[lid] = label.model_copy(update=update)

    # -- the rules --

    def process(self, ev: Event) -> Tagged:
        pid, ts = ev.actor.id, ev.ts
        first = pid not in self.procs
        if first:
            inherited = set()
            parent = ev.actor.parent
            if parent in self.procs:  # rule 4
                inherited |= self.procs[parent].labels
            if parent in self.pending:  # rule 3
                inherited |= self.pending.pop(parent)
            self.procs[pid] = _Proc(
                parent=parent, role=ev.actor.role, labels=set(inherited), ever=set(inherited)
            )
        proc = self.procs[pid]
        fp = ev.object.fingerprint
        new: list[str] = []
        trusted = False

        if ev.type in (EventType.CONTENT_IN, EventType.REQUEST_IN):
            source = ev.attrs.get("source_class")
            if "trusted_source" in ev.attrs:  # rule 6: trusted sources create no label
                trusted = True
            elif source in EXTERNAL_SOURCES and fp is not None:  # rule 1
                label = self._label_for(fp, source, ts, new)
                if ev.actor.role not in self.policy.non_carrier_roles:  # rule 2
                    proc.labels.add(label)
                    proc.ever.add(label)
                if ev.type is EventType.REQUEST_IN:
                    self.requests[(pid, fp)] = label
        elif ev.type is EventType.REQUEST_END and fp is not None:
            ended = self.requests.pop((pid, fp), None)
            if ended is not None:
                proc.labels.discard(ended)
        elif ev.type is EventType.EXEC and fp is not None:  # rule 3
            hit = self.alive(self.fp_labels.get(fp, ()), ts)
            if hit:
                self.pending[pid] = set(hit)
        elif ev.type in (EventType.FILE_WRITE, EventType.PERSIST) and fp is not None:  # rule 5
            persistent = ev.type is EventType.PERSIST or "web_root" in ev.attrs
            edge = "persist" if ev.type is EventType.PERSIST else "write"
            for parent_label in self.alive(proc.labels, ts):
                new.append(self._derive(parent_label, fp, ts, persistent, edge))
            self.written_by[fp] = pid

        actor_labels = self.alive(proc.labels, ts)
        object_labels = self.alive(self.fp_labels.get(fp, ()), ts) if fp is not None else ()
        return Tagged(ev, actor_labels, object_labels, tuple(new), trusted, first)

    def _edge(self, kind: str) -> float:
        """The attenuation a_e of an edge (C11.2); 1.0 unless the policy lists it."""
        return self.policy.math.attenuation.get(kind, 1.0)

    # -- helpers --

    def _next_id(self) -> str:
        self._counter += 1
        return f"L-{self._counter}"

    def _label_for(self, fp: str, source: str, ts, new: list[str]) -> str:
        live = self.alive(self.fp_labels.get(fp, ()), ts)
        if live:
            return max(live, key=lambda i: self.strength(i, ts))
        label = Label(
            label_id=self._next_id(), origin=Origin.EXTERNAL, source_class=SourceClass(source),
            created=ts, strength=1.0,
        )  # fmt: skip
        self.labels[label.label_id] = label
        self.fp_labels.setdefault(fp, set()).add(label.label_id)
        new.append(label.label_id)
        return label.label_id

    def _derive(self, parent_id: str, fp: str, ts, persistent: bool, edge: str = "write") -> str:
        key = (parent_id, fp)
        if key in self.derived:
            existing = self.derived[key]
            if persistent and not self.labels[existing].persistent:
                # v1.4 (A59): becoming persistent freezes the label at the strength it has now. A
                # persistent label does not decay, so leaving the stored strength would restore a
                # label that had faded to the strength it was created with.
                self.labels[existing] = self.labels[existing].model_copy(
                    update={"persistent": True, "strength": min(1.0, self.strength(existing, ts))}
                )
            return existing
        parent = self.labels[parent_id]
        strength = attenuate(self.strength(parent_id, ts), self._edge(edge))
        label = Label(
            label_id=self._next_id(), origin=parent.origin, source_class=parent.source_class,
            created=ts, strength=min(1.0, strength),
            parents=(parent_id,), persistent=persistent,
        )  # fmt: skip
        self.labels[label.label_id] = label
        self.fp_labels.setdefault(fp, set()).add(label.label_id)
        self.derived[key] = label.label_id
        return label.label_id
