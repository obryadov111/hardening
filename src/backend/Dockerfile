FROM python:3.12-slim

WORKDIR /app

# Шрифт с кириллицей для выгрузки снимков в PDF (встроенные шрифты PDF кириллицу не отображают)
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

# Пробы агента — для проверки выгрузки, загруженной через интерфейс (app/services/offline_scan.py):
# сервер выполняет тот же код, что агент с --offline-dir. Каталог agent/ вне контекста сборки бэкенда,
# поэтому он подаётся отдельным контекстом: docker build --build-context agent=./agent ./src/backend
COPY --from=agent probes.py /app/agent/probes.py
ENV HARDENING_AGENT_DIR=/app/agent

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]