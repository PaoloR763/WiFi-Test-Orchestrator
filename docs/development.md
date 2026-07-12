# Desarrollo local de Fases 04 y 05

## Requisitos

- Windows 11 con Docker Desktop y backend WSL2, o Linux con Docker Engine.
- Docker Compose v2 compatible con `docker compose up --wait`.
- PowerShell 7 para los scripts `.ps1`, o una shell POSIX para los scripts `.sh`.

No se requiere instalar Python, Node.js, PostgreSQL, Redis ni herramientas de
lint globalmente. Los comandos de calidad se ejecutan en contenedores Linux.

## Agente desktop de Fase 05

La validación unificada construye `desktop-agent-tools`. También puede ejecutarse
de forma aislada:

```powershell
docker build --file agents/desktop/Dockerfile --target test --tag wto-desktop-agent-test .
docker run --rm wto-desktop-agent-test pytest agents/desktop/tests
```

```sh
docker build --file agents/desktop/Dockerfile --target test --tag wto-desktop-agent-test .
docker run --rm wto-desktop-agent-test pytest agents/desktop/tests
```

Antes del build, `python scripts/sync_desktop_contracts.py --check` comprueba que
el package data deriva sin drift de `shared/contracts/`.
`scripts/test_desktop_wheel.py` construye un wheel y lo instala en un venv
temporal limpio.

## Inicio rápido

Desde la raíz del repositorio:

```powershell
./scripts/generate-env.ps1
docker compose up -d --wait
```

La UI queda disponible en `http://localhost:8080`. El reverse proxy es el único
servicio que publica un puerto. El puerto puede cambiarse temporalmente con
`WTO_HTTP_PORT`.

Comandos equivalentes:

```powershell
./scripts/dev.ps1 up
./scripts/dev.ps1 logs
./scripts/dev.ps1 down
```

```sh
sh scripts/dev.sh up
sh scripts/dev.sh logs
sh scripts/dev.sh down
```

`down` conserva datos. La eliminación de volúmenes requiere una acción separada
y explícita:

```powershell
./scripts/dev.ps1 reset -ConfirmReset
```

```sh
sh scripts/dev.sh reset --confirm
```

## Configuración

`.env.example` es una plantilla no utilizable. Los scripts `generate-env`
crean `.env` ignorado con passwords PostgreSQL y claves independientes. Para
actualizar un `.env` de Fase 03 sin rotar valores existentes, agregue únicamente
las tres claves nuevas de Fase 04 con una de estas operaciones idempotentes:

```powershell
./scripts/generate-env.ps1 --add-missing
```

```sh
sh scripts/generate-env.sh --add-missing
```

El upgrade preserva los bytes existentes, no muestra secretos y usa el CSPRNG
de Python para cada valor faltante. `--force` continúa siendo una operación
destructiva separada que regenera todo el archivo. Compose usa `.env`.

Variables principales:

| Variable | Uso |
|---|---|
| `WTO_ENVIRONMENT` | `development`, `demo`, `test` o `production` |
| `WTO_HTTP_PORT` | Puerto publicado por el proxy; predeterminado `8080` |
| `WTO_LOG_LEVEL` | Nivel de logs JSON |
| `WTO_DEMO_AGENT_TTL_SECONDS` | Ventana transitoria de presencia demo |
| `WTO_ALLOWED_ORIGIN` | Origen exacto aceptado para operaciones con cookie |
| `WTO_TRUSTED_PROXY_CIDRS` | Peers autorizados para aportar `X-Real-IP` |
| `WTO_JWT_SIGNING_KEY` | Firma JWT; mínimo 256 bits |
| `WTO_RATE_LIMIT_HMAC_KEY` | Fingerprints efímeros de rate limit |
| `WTO_AUDIT_SUBJECT_HMAC_KEY` | Fingerprints persistidos en auditoría |
| `WTO_ENROLLMENT_TOKEN_HMAC_KEY` | HMAC exclusivo de EnrollmentToken |
| `WTO_AGENT_CREDENTIAL_HMAC_KEY` | HMAC exclusivo de AgentCredential |
| `WTO_SECRET_REPLAY_ENCRYPTION_KEY` | AEAD de replay secreto por 15 minutos |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | PostgreSQL local |
| `SIM_AGENT_ID`, `SIM_AGENT_DISPLAY_NAME` | Identidad sólo para el simulador |
| `SIM_HEARTBEAT_INTERVAL_SECONDS` | Cadencia de presencia demo |

No se debe usar el archivo de ejemplo como configuración productiva.

## Calidad y validación

PowerShell, Bash y Make ofrecen `build`, `lint`, `format-check`, `typecheck`,
`test`, `smoke`, `migrate` y `validate`. Por ejemplo:

```powershell
./scripts/dev.ps1 validate
```

```sh
sh scripts/dev.sh validate
```

Los cuatro consumidores contractuales pueden ejecutarse de forma explícita:

```powershell
./scripts/dev.ps1 contracts
```

```sh
sh scripts/dev.sh contracts
```

Los servicios de herramientas pertenecen al profile opcional `tools`; el
entorno funcional normal no necesita activar profiles.

Black 25.1.0 toma su configuración central de `backend/pyproject.toml`. Las
migraciones publicadas `20260711_0001`, `20260712_0002` y `20260712_0003` están
excluidas del reformateo; `migrations/env.py`, `20260712_0004`, `src` y `tests`
continúan bajo validación.

## Bootstrap

```powershell
./scripts/dev.ps1 seed
./scripts/bootstrap-admin.ps1 -Username admin
```

El prompt de contraseña es oculto y el administrador debe rotarla al ingresar.

## Límites de seguridad

El deployment local usa HTTP dentro de un host de desarrollo. TLS sigue siendo
obligatorio antes de cualquier despliegue compartido. El simulated-agent no
escucha puertos; smoke crea un token efímero, enrola, rota y envía heartbeat
normativo sin registrar secretos. Smoke usa un project name explícito y, aun
ante errores, elimina sus contenedores, redes y volúmenes, restaura el entorno
de la sesión y falla si detecta recursos residuales por label de Compose.
