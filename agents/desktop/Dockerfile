FROM python:3.12.11-slim-bookworm AS test

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /workspace
COPY agents/desktop ./agents/desktop
COPY shared/contracts ./shared/contracts
COPY scripts/sync_desktop_contracts.py scripts/sync_desktop_contracts.py
COPY scripts/test_desktop_wheel.py scripts/test_desktop_wheel.py
RUN python -m pip install --no-cache-dir --requirement agents/desktop/requirements-dev.lock \
    && mkdir -p /opt/wto-wheelhouse \
    && python -m pip wheel --requirement agents/desktop/requirements.lock \
       --wheel-dir /opt/wto-wheelhouse \
    && python -m pip install --no-cache-dir --no-deps --editable ./agents/desktop

CMD ["pytest", "tests"]
