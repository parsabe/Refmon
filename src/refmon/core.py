"""The core pipeline entry point and the runner that connects sensor, core and enforcer."""

from dataclasses import dataclass, field

from .interfaces import AnyEvent, Core, Enforcer, Sensor
from .schemas import Action, ActionResult, Verdict


class EmptyCore:
    """Accepts every event and produces nothing. The stages replace this one phase at a time."""

    def process(self, event: AnyEvent) -> list[Verdict | Action]:
        return []


@dataclass
class RunReport:
    events: int = 0
    verdicts: list[Verdict] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    results: list[ActionResult] = field(default_factory=list)


def run_pipeline(sensor: Sensor, core: Core, enforcer: Enforcer) -> RunReport:
    """Stream every event from `sensor` through `core`; hand each Action to `enforcer`."""
    report = RunReport()

    def sink(event: AnyEvent) -> None:
        report.events += 1
        for output in core.process(event):
            if isinstance(output, Verdict):
                report.verdicts.append(output)
            else:
                report.actions.append(output)
                report.results.append(enforcer.act(output))

    sensor.emit(sink)
    return report
