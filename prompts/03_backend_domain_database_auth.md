# Prompt 03 - Dominio backend, base de datos, autenticación y RBAC

## Objetivo

Implementar el núcleo de dominio, persistencia, migraciones, usuarios, roles, sesiones y auditoría.

## Prerrequisitos

- Prompt 02 funcional.
- PostgreSQL disponible.

## Alcance

- Modelos y migraciones.
- Auth de usuarios.
- RBAC.
- Auditoría.
- Configuración y errores API.

## Requisitos de implementación

- Modelar User, Role, Permission, Session/RefreshToken, Agent, Device, Capability, TestDefinition, Campaign, Execution, Metric, Artifact, AuditLog y EnrollmentToken.
- Usar UUID y timestamps UTC.
- Implementar access/refresh tokens con rotación y revocación.
- Hash seguro de contraseñas.
- Seeds y comando para crear administrador.
- Auditar login, cambios de rol, tokens, campañas y acciones sensibles.
- Errores estructurados con code, message, details y correlation_id.
- Índices y constraints explícitos.
- No almacenar secretos en texto plano.

## Tests obligatorios

- Migración desde base vacía y downgrade controlado.
- Tests RBAC por endpoint.
- Rotación/revocación de refresh token.
- Auditoría.
- Constraints e idempotencia.

## Documentación obligatoria

- ERD.
- Referencia de roles/permisos.
- Runbook de bootstrap admin.
- Política de retención de auditoría.

## Criterios de aceptación

- Auth y RBAC protegen endpoints.
- Migraciones reproducibles.
- Auditoría identifica actor, acción, recurso y resultado.
- No se filtran secretos.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
