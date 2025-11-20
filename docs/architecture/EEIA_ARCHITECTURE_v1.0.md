# EEIA_ARCHITECTURE_v1.0.md

## 1. Обзор

**EEIA (Ethereal Edge Integrity Architecture)** — это минимальное, но расширяемое ядро
для безопасной маршрутизации трафика IoT/edge-устройств в критически важных доменах:

- медицина (MEDICAL, BODY),
- умные города (SMART_CITY, TRANSPORT),
- промышленность и энергетика (INDUSTRIAL),
- морская инфраструктура (WATER),
- агросектор (AGRICULTURE),
- резервные сценарии (OTHER).

Основная цель EEIA — обеспечить:

1. Чётко определённую доменную модель трафика (Environment + Domain).
2. Прозрачную и проверяемую логику маршрутизации (HybridRouter + PolicyStore).
3. Встроенные точки расширения для:
   - Zero-Trust безопасности (подписи, ключи устройств, ML-scoring),
   - наблюдаемости (метрики, трейсинг),
   - интеграции с существующей инфраструктурой (HTTP, MQTT, TSDB, object storage).

## 2. Модель данных

### 2.1. Environment

`Environment` описывает **физическую среду** доставки:

- `GROUND` — наземная инфраструктура (город, завод, поля),
- `AIR` — БПЛА, авиация, воздушные платформы,
- `ORBIT` — спутники, орбитальные ретрансляторы.

### 2.2. Domain

`Domain` описывает **логическую отрасль/вертикаль**:

- `MEDICAL`, `BODY` — медицина и носимые медицинские устройства,
- `SMART_CITY`, `TRANSPORT` — умные города и транспорт,
- `INDUSTRIAL` — заводы, энергетика, тяжёлая промышленность,
- `WATER` — флот, гидротехника, подводные конструкции,
- `AGRICULTURE` — агросектор, фермы, теплицы,
- `OTHER` — резерв.

### 2.3. Packet

`Packet` — минимальная единица маршрутизации:

- идентификаторы: `packet_id`, `device_id`,
- контекст: `env: Environment`, `domain: Domain`,
- тип: `packet_type` (TELEMETRY, ALERT, CONTROL, HEARTBEAT),
- приоритет: `priority` (LOW, NORMAL, HIGH, CRITICAL),
- данные: `data`, `metadata`,
- опционально: `trace_id` для трассировки сквозь систему.

### 2.4. Policy

`Policy` описывает **правило маршрутизации**:

- область действия: `match_environment`, `match_domain`, `min_priority`,
- целевой endpoint: `target_endpoint` (URL, адрес брокера и т.д.),
- политика хранения: `store_in_timeseries`, `store_in_object_storage`,
- требования безопасности: `require_auth`, `require_integrity_check`, `require_encryption`.

## 3. Ядро маршрутизации

### 3.1. PolicyStore

`PolicyStore` — простое in-memory хранилище политик с API:

- `add(policy)`, `remove(policy_id)`, `all()`,
- `match_for_packet(packet)` — поиск первой подходящей политики.

В боевой системе реализация может быть заменена на:

- распределённый конфиг-сервис,
- базу данных,
- защищённое хранилище политик с аудитом.

### 3.2. HybridRouter

`HybridRouter` принимает `Packet`, опрашивает `PolicyStore` и возвращает `RoutingDecision`:

- `policy` — применённая политика (или `None`),
- `target_endpoint`,
- `store_in_timeseries`, `store_in_object_storage`,
- `should_forward` — решение о немедленной отправке или оффлайн-буфере.

При отсутствии подходящей политики применяется **дефолтное поведение**:

- TELEMETRY/HEARTBEAT/ALERT → сохраняются в TSDB,
- ALERT → дополнительно в объектное хранилище,
- CONTROL → можно не сохранять (по умолчанию).

## 4. Инфраструктурный слой (HTTP API, Docker, K8s)

### 4.1. HTTP API

`eeia.api.http:app` — FastAPI-приложение, предоставляющее:

- `GET /health` — быстрый health-check,
- `POST /v1/policies` — создание/обновление политики,
- `POST /v1/packets/route` — приём `Packet` и возврат `RoutingDecision`,
- `GET /metrics` — Prometheus-подобный экспорт метрик.

### 4.2. Контейнеризация и оркестрация

- `Dockerfile` — минимальный образ на базе `python:3.12-slim`.
- `docker-compose.yml` — локальная оркестрация.
- `infra/k8s/eeia-deployment.yaml` + `infra/k8s/eeia-service.yaml` — деплой и сервис для Kubernetes.

## 5. Наблюдаемость (Observability)

### 5.1. Метрики

`observability/domain_metrics.py`:

- ведёт счётчики по `(domain, env)`:
  - общее количество пакетов,
  - доля routed/offline,
  - сколько пакетов было сохранено в TSDB/объектное хранилище;
- экспортирует данные в Prometheus-подобном формате через `/metrics`.

### 5.2. Трейсинг

`Packet.trace_id` позволяет:

- связывать маршрутизацию с downstream-логами и внешними системами;
- передавать ID через HTTP-заголовки и внутренние очереди.

## 6. Безопасность и Zero-Trust

Базовые принципы и реализация описаны в документе
[`EEIA-Security-v1.0.md`](./specs/EEIA-Security-v1.0.md).

Здесь зафиксировано следующее:

- ядро маршрутизации не зависит от конкретной криптографии,
- security реализуется как **надстройка** поверх Packet/Policy/Router,
- есть готовые модули для:
  - управления ключами устройств,
  - HMAC-подписей Packet,
  - ML-аналитики риска.

## 7. Точки расширения

EEIA изначально спроектирована как расширяемый каркас:

1. **Новые домены**: можно добавлять в Enum `Domain` без ломки модели.
2. **Новые среды**: аналогично через Enum `Environment`.
3. **Новые адаптеры**: HTTP, MQTT, AMQP, gRPC — над HybridRouter.
4. **Интеграция ML**: через `RiskScoringEngine` и Policy-уровень.
5. **PQC и квантовая криптография**: замена реализаций в security-модуле без изменения ядра.
