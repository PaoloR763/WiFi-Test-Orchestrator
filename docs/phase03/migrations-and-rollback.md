# Migraciones y rollback de Fase 03

La cadena es:

1. `20260711_0001`: baseline vacío.
2. `20260712_0002`: identidad, RBAC, sesiones y auditoría.
3. `20260712_0003`: esqueletos mínimos de continuidad.

`alembic check` compara el head con metadata SQLAlchemy. CI prueba upgrade desde
baseline, downgrade a baseline y re-upgrade sobre PostgreSQL descartable.

Para rollback de aplicación, preferir volver a la imagen anterior manteniendo
las tablas aditivas. Un downgrade a `20260711_0001` elimina datos de Fase 03 y
sólo debe ejecutarse después de backup verificado o en una base descartable.
El orden de downgrade elimina primero métricas/artefactos/ejecuciones y termina
con sesiones, RBAC y usuarios.
