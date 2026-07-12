# Mapa del monorepo

| Ruta | Responsabilidad en Fase 02 |
|---|---|
| `backend/` | FastAPI, readiness, logging, middleware, Celery y Alembic |
| `frontend/` | React/Vite y UI mínima consumida mediante el proxy |
| `agents/simulated/` | Proceso outbound-only para smoke tests |
| `agents/` | Límite futuro de agentes desktop |
| `mobile/` | Límite reservado para Android e iOS |
| `shared/` | Límite reservado para contratos de Fase 04 |
| `integrations/` | Límite reservado para adapters externos |
| `deployment/proxy/` | Reverse proxy Nginx no privilegiado |
| `docs/architecture/` | Arquitectura aprobada; no se redefine en Fase 02 |
| `docs/` | Guías operativas y de desarrollo |
| `tests/compose/` | Política estática de Compose |
| `scripts/` | Operación, smoke y guardrails del repositorio |
| `.github/workflows/` | CI Linux basada en contenedores |

Los endpoints y DTOs bajo `/demo` son scaffolding transitorio. No pertenecen a
`shared/`, no aparecen en OpenAPI y deben ser reemplazados en Fases 03 y 04.
