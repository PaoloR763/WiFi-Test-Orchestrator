# Desarrollo local de la Fase 03

## Requisitos

- Windows 11 con Docker Desktop y backend WSL2, o Linux con Docker Engine.
- Docker Compose v2 compatible con `docker compose up --wait`.
- PowerShell 7 para los scripts `.ps1`, o una shell POSIX para los scripts `.sh`.

No se requiere instalar Python, Node.js, PostgreSQL, Redis ni herramientas de
lint globalmente. Los comandos de calidad se ejecutan en contenedores Linux.

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
crean `.env` ignorado con passwords PostgreSQL y tres claves independientes:
JWT, HMAC de rate limit y HMAC de auditoría. Compose usa `.env`.

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

Los servicios de herramientas pertenecen al profile opcional `tools`; el
entorno funcional normal no necesita activar profiles.

## Bootstrap

```powershell
./scripts/dev.ps1 seed
./scripts/bootstrap-admin.ps1 -Username admin
```

El prompt de contraseña es oculto y el administrador debe rotarla al ingresar.

## Límites de seguridad

El deployment local usa HTTP dentro de un host de desarrollo. TLS sigue siendo
obligatorio antes de cualquier despliegue compartido. El simulated-agent no
escucha puertos y sus endpoints demo no son enrolamiento ni inventario normativo.
