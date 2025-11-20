"""
HTTP API поверх ядра EEIA.

Это минимальный референс-слой:
- принимает Packet,
- прогоняет через HybridRouter,
- при необходимости складывает в OfflineCache,
- отдаёт решение в виде JSON.

Для продакшена сюда можно добавить:
- полноценный DI-контейнер,
- аутентификацию,
- версионирование API и пр.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse, PlainTextResponse

from eeia.core.cache import OfflineCache
from eeia.core.models import Packet, Policy
from eeia.core.router import HybridRouter, PolicyStore, RoutingDecision
from eeia.observability.domain_metrics import record_decision_metrics, global_domain_metrics

def create_app(
    cache_path: Path | None = None,
) -> FastAPI:
    """
    Фабрика FastAPI-приложения.

    cache_path:
        Путь к SQLite-базе для оффлайн-кэша.
        В продакшене это может быть внешний Volume или отдельный сервис.
    """
    app = FastAPI(
        title="EEIA Control Plane",
        version="0.1.0",
        description=(
            "Reference HTTP API for Ethereal Edge Integrity Architecture "
            "(routing, policies, offline cache)."
        ),
    )

    # --- инициализация ядра -------------------------------------------------
    policy_store = PolicyStore()
    router = HybridRouter(policy_store)
    cache = OfflineCache(db_path=cache_path or Path("offline_cache.db"))

    # --- служебные эндпоинты ------------------------------------------------
    @app.get("/health", tags=["meta"])
    async def health() -> Dict[str, str]:
        """Простейший healthcheck — удобен для мониторинга и k8s probes."""
        return {"status": "ok"}

    # --- работа с политиками ------------------------------------------------
    @app.post("/v1/policies", response_model=Policy, tags=["policies"])
    async def create_policy(policy: Policy) -> Policy:
        """
        Создать или обновить политику маршрутизации.

        В демо-версии политика сразу попадает в in-memory PolicyStore.
        В реальной системе здесь будет слой персистентности/аудита.
        """
        policy_store.add(policy)
        return policy

    @app.get("/v1/policies", response_model=List[Policy], tags=["policies"])
    async def list_policies() -> List[Policy]:
        """Вернуть все политики, известные данному инстансу EEIA."""
        return list(policy_store._policies.values())

    # --- маршрутизация пакетов ----------------------------------------------
    @app.post("/v1/packets/route", tags=["routing"])
    async def route_packet(packet: Packet) -> JSONResponse:
        """
        Принять Packet, вычислить решение и при необходимости
        положить его в оффлайн-очередь.

        Для демо мы:
        - всегда возвращаем решение в ответе,
        - кладём пакет в OfflineCache, если should_forward == False.
        """
        decision: RoutingDecision = router.route(packet)

        if not decision.should_forward:
            # если по политике нельзя/не нужно форвардить — сохраняем локально
            cache.enqueue(packet)

        body: Dict[str, Any] = {
            "packet_id": packet.packet_id,
            "device_id": packet.device_id,
            "decision": {
                "policy_id": decision.policy.policy_id  # type: ignore[union-attr]
                if decision.policy
                else None,
                "target_endpoint": decision.target_endpoint,
                "store_in_timeseries": decision.store_in_timeseries,
                "store_in_object_storage": decision.store_in_object_storage,
                "should_forward": decision.should_forward,
            },
        }
        return JSONResponse(body, status_code=200)

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        """
        Очень простой endpoint для съёма метрик Prometheus-подобным образом.
        """
        text = global_domain_metrics.as_prometheus_text()
        return PlainTextResponse(text, media_type="text/plain; version=0.0.4")

    return app


# Экземпляр по умолчанию для `uvicorn eeia.api.http:app`
app = create_app()
