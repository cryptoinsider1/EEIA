# src/eeia/edge_ml/hooks.py
from __future__ import annotations

"""
ML-hook для риск-скоринга Packet.

Задачи модуля:
- Определить минимальный контракт ScoringResult / PacketScorer.
- Дать простую эвристическую реализацию HeuristicPacketScorer,
  которую в проде можно заменить на вызов внешней ML-модели.

Важно: модуль НЕ тянет внешние зависимости (httpx и т.п.),
всё синхронно и детерминированно, идеально для юнит-тестов.
"""

from dataclasses import dataclass
from typing import List, Protocol

from eeia.core.models import Packet, PacketPriority, Domain


@dataclass(frozen=True)
class ScoringResult:
    """
    Результат ML/эвристического скоринга пакета.

    score  — риск в диапазоне [0.0, 1.0],
    label  — категориальная оценка ("low" / "medium" / "high"),
    reasons — список факторов, повлиявших на оценку (для аудита/объяснимости).
    """

    score: float
    label: str
    reasons: List[str]


class PacketScorer(Protocol):
    """
    Контракт для любой реализации скоринга пакетов.

    Внешние ML-сервисы, онлайновые модели и т.п. могут реализовать
    этот протокол.
    """

    def score(self, packet: Packet) -> ScoringResult:
        ...


class HeuristicPacketScorer:
    """
    Встроенный эвристический скорер.

    Использует:
    - Domain (BODY, MEDICAL, WATER, TRANSPORT, AGRICULTURE),
    - Priority,
    - размер пакета.

    Это не "настоящий" ML, а понятный baseline, который:
    - даёт разумные значения score/label;
    - легко заменить на полноценную ML-модель без изменения API.
    """

    def score(self, packet: Packet) -> ScoringResult:
        reasons: List[str] = []
        score = 0.0

        # --- домен ----------------------------------------------------------
        if packet.domain is Domain.BODY:
            score += 0.4
            reasons.append("domain:body")
        elif packet.domain is Domain.MEDICAL:
            score += 0.3
            reasons.append("domain:medical")
        elif packet.domain is Domain.WATER:
            score += 0.2
            reasons.append("domain:water")
        elif packet.domain is Domain.TRANSPORT:
            score += 0.2
            reasons.append("domain:transport")
        elif packet.domain is Domain.AGRICULTURE:
            score += 0.1
            reasons.append("domain:agriculture")

        # --- приоритет ------------------------------------------------------
        if packet.priority is PacketPriority.CRITICAL:
            score += 0.5
            reasons.append("priority:critical")
        elif packet.priority is PacketPriority.HIGH:
            score += 0.3
            reasons.append("priority:high")
        elif packet.priority is PacketPriority.NORMAL:
            score += 0.1
            reasons.append("priority:normal")

        # --- размер пакета --------------------------------------------------
        if packet.size_bytes > 1024 * 1024:
            score += 0.2
            reasons.append("size:>1MB")

        # --- нормализация и label ------------------------------------------
        score = max(0.0, min(1.0, score))

        if score >= 0.7:
            label = "high"
        elif score >= 0.4:
            label = "medium"
        else:
            label = "low"

        reasons.append(f"label:{label}")

        return ScoringResult(score=score, label=label, reasons=reasons)
