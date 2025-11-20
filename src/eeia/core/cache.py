from __future__ import annotations

"""Offline cache and retry logic for intermittent connectivity.

В реальных IoT-сетях связь часто нестабильна: обрывы, потеря пакетов,
долгие задержки. Задача этого модуля – обеспечить «буфер» между
устройствами/шлюзами и центральной частью EEIA:

- временно сохранять пакеты, которые не удалось доставить;
- периодически пытаться отправить их повторно;
- предоставлять простую статистику (сколько пакетов в очереди и т.п.).

Здесь реализована минимальная reference-версия на sqlite3, чтобы:
- не тянуть внешние зависимости;
- можно было запускать и тестировать в любом окружении.

В продакшене  заменить это на Kafka/RabbitMQ/Redis Streams и т.д.,
сохранив интерфейс OfflineCache.
"""

from dataclasses import dataclass
import json
import sqlite3
from pathlib import Path
from typing import Iterable, List

from .models import Packet


@dataclass(frozen=True)
class CachedPacket:
    """Пакет, извлечённый из оффлайн-очереди.

    Содержит:
    - packet: восстановленный объект Packet;
    - internal_id: внутренний идентификатор записи в БД (для удаления).
    """

    internal_id: int
    packet: Packet


class OfflineCache:
    """Простая оффлайн-очередь на sqlite.

    Таблица `offline_packets` имеет вид:
    - id INTEGER PRIMARY KEY AUTOINCREMENT
    - packet_id TEXT
    - device_id TEXT
    - created_at TEXT (ISO8601)
    - payload_json TEXT (полный Packet в JSON)

    Такой формат:
    - легко читать/отлаживать;
    - не завязан на конкретную схему БД;
    - остаётся переносимым.
    """

    def __init__(self, db_path: Path | str = "./eeia_offline_cache.db") -> None:
        self._db_path = Path(db_path)
        self._init_db()

    # --- базовая инициализация ------------------------------------------------

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offline_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    packet_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    # --- основные операции ----------------------------------------------------

    def enqueue(self, packet: Packet) -> None:
        """Положить пакет в оффлайн-очередь.

        Используем сериализацию через `model_dump()` → JSON.
        Важно: в очереди могут храниться только уже прошедшие базовую валидацию Packet.
        """
        payload = packet.model_dump(mode="json")
        payload_json = json.dumps(payload, ensure_ascii=False)

        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO offline_packets (packet_id, device_id, created_at, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    packet.packet_id,
                    packet.device_id,
                    payload["created_at"],
                    payload_json,
                ),
            )
            conn.commit()

    def dequeue_batch(self, limit: int = 100) -> List[CachedPacket]:
        """Извлечь не более `limit` пакетов из очереди (без удаления).

        Возвращает список CachedPacket с их внутренними ID.
        Удаление нужно делать отдельным вызовом `delete_many`, когда
        система убедилась, что повторная отправка прошла успешно.
        """
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute(
                """
                SELECT id, payload_json
                FROM offline_packets
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()

        result: List[CachedPacket] = []
        for row_id, payload_json in rows:
            data = json.loads(payload_json)
            packet = Packet.model_validate(data)
            result.append(CachedPacket(internal_id=row_id, packet=packet))

        return result

    def delete_many(self, internal_ids: Iterable[int]) -> None:
        """Удалить записи по их внутренним ID.

        Обычно вызывается после успешной повторной отправки пакетов.
        """
        ids = list(internal_ids)
        if not ids:
            return

        placeholders = ",".join("?" for _ in ids)
        query = f"DELETE FROM offline_packets WHERE id IN ({placeholders})"

        with sqlite3.connect(self._db_path) as conn:
            conn.execute(query, ids)
            conn.commit()

    def count(self) -> int:
        """Вернуть количество пакетов в очереди."""
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM offline_packets")
            (cnt,) = cursor.fetchone()
        return int(cnt)

    def clear(self) -> None:
        """Полностью очистить оффлайн-очередь (для тестов/отладки)."""
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("DELETE FROM offline_packets")
            conn.commit()
