# Backend de identidad de la Fase 03

La Fase 03 implementa autenticación local, sesiones, RBAC humano y auditoría.
Las rutas bajo `/api/internal/v1` son internas y provisionales: no constituyen
el contrato normativo de la Fase 04.

Documentos:

- [ERD](erd.md)
- [Roles y permisos](rbac.md)
- [Contraseñas, sesiones, CSRF y proxy](authentication.md)
- [Auditoría y retención](audit.md)
- [Bootstrap](bootstrap-admin.md)
- [Migraciones y rollback](migrations-and-rollback.md)

Los modelos `Agent`, `Device`, `Capability`, `TestDefinition`, `Campaign`,
`Execution`, `Metric`, `Artifact` y `EnrollmentToken` son esqueletos de
continuidad. No poseen API funcional, manifests, estados ejecutables ni wire
formats. Enrolamiento, credenciales máquina y contratos pertenecen a Fase 04.

## API interna provisional

| Método y ruta | Protección |
|---|---|
| `POST /api/internal/v1/auth/login` | Rate limit Redis |
| `POST /api/internal/v1/auth/refresh` | Cookie y Origin |
| `POST /api/internal/v1/auth/logout` | Bearer, cookie context y Origin |
| `POST /api/internal/v1/auth/logout-all` | Bearer y Origin |
| `GET /api/internal/v1/auth/me` | Bearer |
| `POST /api/internal/v1/auth/change-password` | Bearer y Origin |
| `/api/internal/v1/admin/users*` | Permisos `users.*` |
| `/api/internal/v1/rbac/*` | `roles.read` o `permissions.read` |
| `GET /api/internal/v1/admin/protected` | `admin.protected_read` |
| `GET /api/internal/v1/audit/events` | `audit.read`, máximo 100 |

Health permanece público. `/demo/agents*` continúa como regresión transitoria
de Fase 02, sólo en development/demo y fuera de OpenAPI.

## Límites conocidos

- El MVP no ofrece HA ni un proveedor de identidad externo.
- HS256 usa un único trust domain; incorporar validadores independientes exige
  revisar firma asimétrica y lifecycle de claves.
- La reutilización estricta de refresh revoca la familia incluso si proviene de
  dos requests legítimos concurrentes.
- TLS sigue siendo responsabilidad del deployment fuera del entorno local.
- La política de purga y legal hold de auditoría se implementará en una fase
  operativa posterior.
