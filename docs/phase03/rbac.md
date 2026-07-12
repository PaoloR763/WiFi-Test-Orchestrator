# Roles y permisos humanos

La autorización es deny-by-default. Los endpoints requieren permisos mediante
dependencies reutilizables; no comparan nombres de rol.

Roles builtin únicos:

- `administrator`: todos los permisos explícitos existentes.
- `test_manager`: lectura de usuarios, roles, permisos y auditoría.
- `operator`: lectura de roles y permisos.
- `viewer`: lectura de roles y permisos.

No existe un rol humano `agent`. Identidad y autorización máquina pertenecen a
Fase 04.

Permisos iniciales: `users.read`, `users.create`, `users.update`,
`users.roles_manage`, `sessions.revoke`, `roles.read`, `permissions.read`,
`audit.read` y `admin.protected_read`.

Los seeds hacen upsert por key estable, agregan permisos faltantes y no eliminan
asignaciones personalizadas. Retirar un rol toma efecto inmediatamente porque
cada request protegido consulta PostgreSQL. Un advisory transaction lock
serializa desactivación o retiro administrativo y evita quedar sin administrador.
