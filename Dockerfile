FROM python:3.12-slim

# Не буферизуем вывод, чтобы логи сразу были видны
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Копируем только то, что нужно для установки
COPY pyproject.toml ./
COPY src ./src

# Устанавливаем зависимости и сам пакет EEIA
RUN python -m pip install --upgrade pip && \
    python -m pip install "uvicorn[standard]" fastapi && \
    python -m pip install .

# Порт API
EXPOSE 8000

# Стартуем FastAPI через uvicorn
CMD ["uvicorn", "eeia.api.http:app", "--host", "0.0.0.0", "--port", "8000"]
