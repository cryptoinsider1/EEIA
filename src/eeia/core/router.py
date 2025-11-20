from __future__ import annotations

"""
Hybrid router and routing policies for EEIA.

Модуль отвечает за принятие решения, что делать с входящим Packet:

- какую политику применить;
- куда отправить (target_endpoint);
- где хранить (time-series / object storage);
- какие базовые требования безопасности должны быть соблюдены.

Важно:
- здесь нет привязки к конкретным протоколам (MQTT/HTTP и т.д.);
- это чистая доменная логика, которую затем используют адаптеры.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

from .models import (
    Domain,
    Environment,
    Packet,
    PacketPriority,
    PacketType,
    Policy,
)


@dataclass(frozen=True)
class RoutingDecision:
    """
    Результат решения роутера для конкретного пакета.

    Это минимальный, но расширяемый контракт между ядром и
    инфраструктурными адаптерами:

    - packet — сам пакет (может быть обогащён метаданными),
    - policy — выбранная политика (или None, если совпадений нет),
    - target_endpoint — целевой endpoint (URL, адрес брокера и т.п.),
    - store_in_timeseries — флаг сохранения в TSDB,
    - store_in_object_storage — флаг сохранения в объектном хранилище,
    - should_forward — отправлять ли пакет «дальше по цепочке»,
    - reasons — человекочитаемый список причин/факторов решения.
    """

    packet: Packet
    policy: Optional[Policy]
    target_endpoint: Optional[str]
    store_in_timeseries: bool
    store_in_object_storage: bool
    should_forward: bool = True
    reasons: List[str] = field(default_factory=list)


class PolicyStore:
    """
    Простое in-memory хранилище политик.

    В реальной системе это может быть БД/конфиг-сервис/центральный реестр.
    Здесь – минимальная реализация для демонстрации и тестов.
    """

    def __init__(self, policies: Optional[Iterable[Policy]] = None) -> None:
        self._policies: List[Policy] = list(policies or [])

    # --- управление политиками -------------------------------------------------

    def upsert(self, policy: Policy) -> None:
        """
        Добавить или заменить политику по её идентификатору.

        Если политика с таким ID уже есть – удаляем и добавляем заново.
        """
        self.remove(policy.policy_id)
        self._policies.append(policy)

    # alias для совместимости с существующим кодом/тестами
    def add(self, policy: Policy) -> None:
        self.upsert(policy)

    def remove(self, policy_id: str) -> None:
        """Удалить политику по ID (если её нет – тихо ничего не делаем)."""
        self._policies = [p for p in self._policies if p.policy_id != policy_id]

    def all(self) -> List[Policy]:
        """Вернуть копию списка всех политик (защита от внешних мутаций)."""
        return list(self._policies)

    # --- поиск подходящей политики --------------------------------------------

    def match_for_packet(self, packet: Packet) -> Optional[Policy]:
        """
        Найти первую политику, подходящую под данный пакет.

        Правила сопоставления:
        - если у политики задан `match_environment`, он должен совпадать с packet.env;
        - если задан `match_domain`, он должен совпадать с packet.domain;
        - если задан `min_priority`, приоритет пакета должен быть не ниже.
        Порядок политик имеет значение: первая подходящая выигрывает.
        """
        for policy in self._policies:
            if policy.match_environment is not None and policy.match_environment is not packet.env:
                continue

            if policy.match_domain is not None and policy.match_domain is not packet.domain:
                continue

            if policy.min_priority is not None:
                if _priority_order(packet.priority) < _priority_order(policy.min_priority):
                    continue

            return policy

        return None


def _priority_order(priority: PacketPriority) -> int:
    """Числовой порядок приоритетов для удобного сравнения приоритетов."""
    order = {
        PacketPriority.LOW: 0,
        PacketPriority.NORMAL: 1,
        PacketPriority.HIGH: 2,
        PacketPriority.CRITICAL: 3,
    }
    return order[priority]


class HybridRouter:
    """
    Гибридный роутер EEIA.
    Его задача – на основе Packet и набора Policy выдать RoutingDecision.
    В «боевой» системе роутер не отправляет данные сам, а лишь решает:
    - куда (endpoint) и как (хранить/не хранить) их передавать;
    - нужна ли дополнительная обработка на следующих слоях.

    Здесь реализуется только чистая логика выбора.
    """

    def __init__(self, policy_store: Optional[PolicyStore] = None) -> None:
        self.policy_store = policy_store or PolicyStore()

    # --- основной метод маршрутизации -----------------------------------------

    def route(self, packet: Packet) -> RoutingDecision:
        """
        Принять решение по маршрутизации пакета.

        Если ни одна политика не совпала, применяется дефолтное поведение:
        - пакеты TELEMETRY и HEARTBEAT сохраняем в TSDB;
        - ALERT дополнительно считаем критичным с точки зрения хранения;
        - CONTROL можно обрабатывать без хранения (по умолчанию).
        Target endpoint в этом случае остаётся None – это сигнал
        инфраструктурному коду использовать значение по умолчанию.
        В текущей версии `should_forward` всегда True — то есть решение
        «не форвардить» и класть в оффлайн-очередь будет на более высоком слое
        (например, по состоянию внешних сервисов).
        """
        reasons: List[str] = []

        policy = self.policy_store.match_for_packet(packet)

        if policy is not None:
            reasons.append(f"matched_policy:{policy.policy_id}")

            target = str(policy.target_endpoint) if policy.target_endpoint else None

            return RoutingDecision(
                packet=packet,
                policy=policy,
                target_endpoint=target,
                store_in_timeseries=policy.store_in_timeseries,
                store_in_object_storage=policy.store_in_object_storage,
                should_forward=True,
                reasons=reasons,
            )

        # --- дефолтное поведение, если политика не найдена --------------------
        reasons.append("no_matching_policy")

        store_ts = packet.packet_type in {
            PacketType.TELEMETRY,
            PacketType.HEARTBEAT,
            PacketType.ALERT,
        }
        store_obj = packet.packet_type is PacketType.ALERT

        return RoutingDecision(
            packet=packet,
            policy=None,
            target_endpoint=None,
            store_in_timeseries=store_ts,
            store_in_object_storage=store_obj,
            should_forward=True,
            reasons=reasons,
        )

    # --- вспомогательные методы -----------------------------------------------

    def add_policies(self, policies: Sequence[Policy]) -> None:
        """Массовое добавление/обновление политик."""
        for policy in policies:
            self.policy_store.upsert(policy)

    def clear_policies(self) -> None:
        """Удалить все политики (для тестов или перезагрузки конфигурации)."""
        for policy in list(self.policy_store.all()):
            self.policy_store.remove(policy.policy_id)
