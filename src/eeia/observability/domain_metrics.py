from __future__ import annotations

"""
Domain-level traffic metrics for EEIA.
- Подсчёт количества пакетов по (domain, env).
- Разделение routed/offline/ts/object.
- Экспорт в Prometheus-подобном текстовом формате.
"""

from dataclasses import dataclass, field
from typing import Dict, Tuple

from eeia.core.models import Domain, Environment
from eeia.core.router import RoutingDecision


@dataclass
class DomainCounters:
    total: int = 0
    routed: int = 0
    offline: int = 0
    ts_stored: int = 0
    obj_stored: int = 0


@dataclass
class DomainTrafficMetrics:
    _counters: Dict[Tuple[str, str], DomainCounters] = field(default_factory=dict)

    def _key(self, domain: Domain, env: Environment) -> Tuple[str, str]:
        return (domain.value, env.value)

    def _get(self, domain: Domain, env: Environment) -> DomainCounters:
        key = self._key(domain, env)
        if key not in self._counters:
            self._counters[key] = DomainCounters()
        return self._counters[key]

    def record_decision(self, decision: RoutingDecision) -> None:
        domain = decision.packet.domain
        env = decision.packet.env
        c = self._get(domain, env)
        c.total += 1
        if decision.should_forward:
            c.routed += 1
        else:
            c.offline += 1
        if decision.store_in_timeseries:
            c.ts_stored += 1
        if decision.store_in_object_storage:
            c.obj_stored += 1

    def as_prometheus_text(self) -> str:
        """Генерация простого Prometheus-подобного экспорта."""
        lines = []
        for (domain, env), c in self._counters.items():
            labels = f'domain="{domain}",env="{env}"'
            lines.append(f'eeia_packets_total{{{labels}}} {c.total}')
            lines.append(f'eeia_packets_routed_total{{{labels}}} {c.routed}')
            lines.append(f'eeia_packets_offline_total{{{labels}}} {c.offline}')
            lines.append(f'eeia_packets_ts_stored_total{{{labels}}} {c.ts_stored}')
            lines.append(f'eeia_packets_obj_stored_total{{{labels}}} {c.obj_stored}')
        return "\n".join(lines) + "\n"


global_domain_metrics = DomainTrafficMetrics()


def record_decision_metrics(decision: RoutingDecision) -> None:
    global_domain_metrics.record_decision(decision)
