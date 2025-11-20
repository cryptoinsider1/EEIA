# EEIA-Security-v1.0.md

## 1. Цели и допущения

EEIA применяется в доменах с повышенными требованиями к безопасности:

- медицина и носимые устройства (MEDICAL, BODY),
- критическая инфраструктура (SMART_CITY, INDUSTRIAL, WATER, AGRICULTURE),
- транспорт и логистика (TRANSPORT).

Модель безопасности EEIA опирается на принципы:

1. **Zero-Trust**: никакое устройство, сегмент сети или узел по умолчанию не считается доверенным.
2. **Defense in Depth**: несколько слоёв защиты от устройства до уровня приложений.
3. **Cryptographic Integrity**: целостность трафика проверяема криптографически.
4. **Auditability**: все значимые решения (маршрутизация, блокировки) подлежат аудиту.
5. **Domain-Aware Security**: домены `BODY`, `MEDICAL`, `WATER`, `AGRICULTURE` имеют повышенные требования.

## 2. Уровни защиты

### 2.1. Уровень идентичности устройства (Device Identity)

Главная сущность — `DeviceKey`:

- `device_id` — уникальный идентификатор узла,
- `key_id` — идентификатор ключа,
- `secret`/`public_key` — ключ/секрет для подписи,
- `algorithm` — используемый алгоритм (например, `HS256`).

Хранилище ключей: `DeviceKeyStore`:

- `register(key)` — регистрация нового ключа;
- `get_active_key(device_id)` — получение активного ключа устройства;
- `revoke(device_id)` — отзыв ключа.

В боевой системе `DeviceKeyStore` отображает внешний KMS/HSM/Vault.

### 2.2. Уровень целостности пакетов (Packet Integrity)

Подпись и проверка Packet реализованы через HMAC:

- `sign_packet_hmac(packet, key: DeviceKey) -> str`,
- `verify_packet_hmac(packet, signature, key: DeviceKey) -> bool`.

Каноническая сериализация `Packet`:

- фиксированный порядок полей,
- строковое представление, стабильное для подписи,
- в будущих версиях может быть заменено на protobuf/CBOR.

Для доменов `BODY`/`MEDICAL` рекомендуется:

- **обязательная подпись** каждого Packet;
- политика маршрутизации, требующая `require_integrity_check=True`.

### 2.3. Валидация входа в роутер (Entry Validation)

Функция `validate_packet_entry` выполняет:

1. Проверку наличия активного `DeviceKey` для `packet.device_id`.
2. При наличии подписи — проверку HMAC.
3. Запрос в ML-движок риска (если он настроен).

Результат: `EntryValidationResult`:

- `ok` / `blocked`,
- `reason` (unknown_device, invalid_signature, ml_risk_block),
- `risk_score`,
- `strict_audit` — включить ли усиленный аудит.

Рекомендуемый паттерн:

```text
HTTP/MQTT → security.validate_packet_entry → HybridRouter.route → delivery
