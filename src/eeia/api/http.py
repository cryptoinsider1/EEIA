from __future__ import annotations

"""
HTTP API поверх ядра EEIA.

Роль этого слоя:
- принимает Packet (JSON → доменная модель),
- прогоняет через HybridRouter,
- при необходимости складывает в OfflineCache,
- отдаёт решение в виде JSON-ответа,
- экспонирует базовые метрики и healthcheck.

Дополнительно:
- Zero-Trust слой через HMAC-подпись пакета:
  - заголовки X-EEIA-Key-Id / X-EEIA-Signature;
  - переменная окружения EEIA_SECURITY_ENFORCE=true делает подпись обязательной.
- простой trace_id через X-Request-Id:
  - если заголовок не пришёл — генерируем UUID4,
  - возвращаем его в теле и в заголовке X-Request-Id.
- опциональный ML-hook для риск-скоринга Packet:
  - можно передать кастомный PacketScorer;
  - либо включить встроенный HeuristicPacketScorer через EEIA_ML_SCORING_ENABLED.
"""

import os
import uuid
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from eeia.core.cache import OfflineCache
from eeia.core.models import Packet, Policy
from eeia.core.router import HybridRouter, PolicyStore, RoutingDecision
from eeia.observability.domain_metrics import (
    record_decision_metrics,
    global_domain_metrics,
)
from eeia.security.packet_security import device_keystore, verify_packet_hmac
from eeia.edge_ml.hooks import PacketScorer, ScoringResult, HeuristicPacketScorer


def create_app(
    cache_path: Path | None = None,
    packet_scorer: PacketScorer | None = None,
) -> FastAPI:
    """
    Фабрика FastAPI-приложения.

    cache_path:
        Путь к SQLite-базе для оффлайн-кэша.
        В продакшене это может быть внешний Volume или отдельный сервис.

    packet_scorer:
        Опциональный ML-скорер. Если не передан и
        EEIA_ML_SCORING_ENABLED=true — включается встроенный
        HeuristicPacketScorer.
    """
    app = FastAPI(
        title="EEIA Control Plane",
        version="0.1.0",
        description=(
            "Reference HTTP API for Ethereal Edge Integrity Architecture "
            "(routing, policies, offline cache, observability, security, ML-hooks)."
        ),
    )

    # --- инициализация ядра -------------------------------------------------
    policy_store = PolicyStore()
    router = HybridRouter(policy_store)
    cache = OfflineCache(db_path=cache_path or Path("offline_cache.db"))

    # --- ML-скорер ----------------------------------------------------------
    # ЛИБО берём то, что передали снаружи,
    # ЛИБО, если включён флаг, поднимаем встроенный HeuristicPacketScorer.
    ml_scorer: PacketScorer | None = packet_scorer
    if ml_scorer is None and os.getenv("EEIA_ML_SCORING_ENABLED", "false").lower() == "true":
        ml_scorer = HeuristicPacketScorer()

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
        policy_store.upsert(policy)
        return policy

    @app.get("/v1/policies", response_model=List[Policy], tags=["policies"])
    async def list_policies() -> List[Policy]:
        """Вернуть все политики, известные данному инстансу EEIA."""
        return policy_store.all()

    # --- маршрутизация пакетов ----------------------------------------------
    @app.post("/v1/packets/route", tags=["routing"])
    async def route_packet(
        packet: Packet,
        x_eeia_key_id: str | None = Header(default=None, alias="X-EEIA-Key-Id"),
        x_eeia_signature: str | None = Header(default=None, alias="X-EEIA-Signature"),
        x_request_id: str | None = Header(default=None, alias="X-Request-Id"),
    ) -> JSONResponse:
        """
        Принять Packet, вычислить решение и при необходимости
        положить его в оффлайн-очередь.

        Zero-Trust слой:
        - если переданы X-EEIA-Key-Id и X-EEIA-Signature, выполняется HMAC-проверка;
        - если включён флаг EEIA_SECURITY_ENFORCE=true, подпись становится обязательной.

        Трейсинг:
        - trace_id берётся из X-Request-Id, если есть;
        - иначе генерируется uuid4;
        - возвращается в JSON и в заголовке X-Request-Id.

        ML-hook:
        - если сконфигурирован ml_scorer, добавляем в ответ блок decision.ml.
        """
        # --- trace_id --------------------------------------------------------
        trace_id = x_request_id or str(uuid.uuid4())

        # --- Zero-Trust флаг -------------------------------------------------
        enforce = os.getenv("EEIA_SECURITY_ENFORCE", "false").lower() == "true"

        # --- Zero-Trust-проверка подписи ------------------------------------
        if x_eeia_signature or enforce:
            # если хотя бы один заголовок есть ИЛИ включён enforce — требуем оба
            if not x_eeia_signature or not x_eeia_key_id:
                raise HTTPException(
                    status_code=401,
                    detail=(
                        "Missing EEIA security headers "
                        "(X-EEIA-Key-Id / X-EEIA-Signature)"
                    ),
                )

            sec_result = verify_packet_hmac(
                packet=packet,
                signature=x_eeia_signature,
                device_id=packet.device_id,
                key_id=x_eeia_key_id,
                keystore=device_keystore,
            )

            if not sec_result.ok:
                raise HTTPException(
                    status_code=401,
                    detail=f"Invalid packet signature: {sec_result.reason}",
                )

        # --- маршрутизация ---------------------------------------------------
        decision: RoutingDecision = router.route(packet)

        # --- метрики домена (оборачиваем, чтобы не падать из-за метрик) -----
        try:
            record_decision_metrics(global_domain_metrics, packet, decision)
        except Exception:
            pass

        # --- ML-скоринг (опционально) ---------------------------------------
        ml_block: Dict[str, Any] | None = None
        if ml_scorer is not None:
            ml_res: ScoringResult = ml_scorer.score(packet)
            ml_block = {
                "score": ml_res.score,
                "label": ml_res.label,
                "reasons": ml_res.reasons,
            }

        # --- оффлайн-кэш -----------------------------------------------------
        if not decision.should_forward:
            cache.enqueue(packet)

        body: Dict[str, Any] = {
            "trace_id": trace_id,
            "packet_id": packet.packet_id,
            "device_id": packet.device_id,
            "decision": {
                "policy_id": decision.policy.policy_id if decision.policy else None,
                "target_endpoint": decision.target_endpoint,
                "store_in_timeseries": decision.store_in_timeseries,
                "store_in_object_storage": decision.store_in_object_storage,
                "should_forward": decision.should_forward,
                "ml": ml_block,
            },
        }

        response = JSONResponse(status_code=200, content=body)
        # дублируем trace_id в заголовок, чтобы его мог подхватить gateway/ingress
        response.headers["X-Request-Id"] = trace_id
        return response

    # --- метрики для Prometheus ---------------------------------------------
    @app.get("/metrics", tags=["meta"])
    async def metrics() -> PlainTextResponse:
        """
        Endpoint для съёма метрик в формате, совместимом с Prometheus.
        """
        text = global_domain_metrics.as_prometheus_text()
        return PlainTextResponse(text, media_type="text/plain; version=0.0.4")

    return app


# Экземпляр по умолчанию для `uvicorn eeia.api.http:app`
app = create_app()
