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

# Два процесса uvicorn — по числу CPU контейнера (deploy/restart_backend.sh: --cpus 2): разбор отчёта агента
# занимает процессор, и один процесс Python упирался в одно ядро (нагрузочный тест: 1000 хостов).
# uvicorn берёт число процессов из WEB_CONCURRENCY; переопределяется при запуске контейнера.
ENV WEB_CONCURRENCY=2

# Не root: процесс веб-сервера не может изменить свой код и образ (проверка docker.no_root_user_explicit
# нашего же пака docker). Записывать ему некуда, кроме /tmp (импорт БДУ — deploy/update_bdu.sh).
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]