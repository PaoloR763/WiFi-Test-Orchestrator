FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10002 simulated \
    && useradd --uid 10002 --gid simulated --create-home --shell /usr/sbin/nologin simulated

WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock
COPY app.py ./

USER simulated
CMD ["python", "app.py"]
