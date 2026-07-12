FROM python:3.12.11-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH=/home/wto/.local/bin:$PATH

RUN groupadd --gid 10001 wto \
    && useradd --uid 10001 --gid wto --create-home --shell /usr/sbin/nologin wto

WORKDIR /app

COPY backend/requirements.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY backend/alembic.ini ./
COPY backend/migrations ./migrations
COPY backend/src ./src

RUN mkdir -p /var/lib/wto/artifacts \
    && chown -R wto:wto /app /var/lib/wto

USER wto

FROM base AS runtime

FROM base AS test
USER root
COPY backend/requirements-dev.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements-dev.lock
COPY backend/pyproject.toml ./
COPY backend/tests ./tests
COPY scripts ./scripts
COPY shared ./shared
COPY agents/desktop /app/agents/desktop
RUN python -m pip install --no-cache-dir --editable '/app/agents/desktop[dev]'
RUN chown -R wto:wto /app
USER wto
