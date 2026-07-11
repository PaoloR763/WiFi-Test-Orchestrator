# Prompt 02 - Monorepo y servidor Windows-first portable

## Objetivo

Crear el esqueleto ejecutable del monorepo y un entorno local reproducible en Windows 11 mediante Docker Desktop/WSL2.

## Prerrequisitos

- Prompt 01 completado y ADRs aprobados.

## Alcance

- Monorepo.
- Docker Compose.
- Backend mínimo.
- Frontend mínimo.
- PostgreSQL, Redis, reverse proxy y artifact store local.
- Scripts PowerShell y Bash.
- CI básica.

## Requisitos de implementación

- Crear carpetas `backend`, `frontend`, `agents`, `mobile`, `shared`, `integrations`, `deployment`, `docs`, `tests` y `scripts`.
- Usar imágenes Linux OCI y volúmenes/rutas portables.
- Agregar `.env.example`, profiles de Compose, health checks y readiness.
- Agregar `Makefile` y scripts PowerShell equivalentes.
- Agregar endpoint `/health/live` y `/health/ready`.
- Crear agente simulado para smoke tests.
- No exponer Redis/PostgreSQL fuera de la red interna por defecto.
- Configurar logs estructurados y correlation IDs desde el inicio.

## Tests obligatorios

- Smoke test de Compose desde entorno limpio.
- Health checks.
- Test de frontend que consume backend.
- CI en Linux para backend/frontend.
- Validar que no haya rutas absolutas de Windows en código.

## Documentación obligatoria

- Guía Windows + WSL2.
- Guía alternativa Linux.
- Mapa del repositorio.
- Troubleshooting de puertos, certificados y volúmenes.

## Criterios de aceptación

- `docker compose up` levanta todos los servicios.
- Un usuario puede abrir frontend y ver estado del sistema.
- Un agente simulado aparece en inventario.
- La CI pasa.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
