FROM python:3.12.11-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH=/home/wto/.local/bin:$PATH

RUN groupadd --gid 10001 wto \
    && useradd --uid 10001 --gid wto --create-home --shell /usr/sbin/nologin wto

WORKDIR /app

COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY alembic.ini ./
COPY migrations ./migrations
COPY src ./src

RUN mkdir -p /var/lib/wto/artifacts \
    && chown -R wto:wto /app /var/lib/wto

USER wto

FROM base AS runtime

FROM base AS test
USER root
COPY requirements-dev.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements-dev.lock
COPY pyproject.toml ./
COPY tests ./tests
RUN chown -R wto:wto /app
USER wto
