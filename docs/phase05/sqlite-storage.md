# Persistencia SQLite

## Tablas

La migración local `0001_initial` crea:

- `schema_migrations`, con versión y checksum;
- `agent_identity` y `runtime_state`;
- `capability_manifests`;
- `inbox_tasks`, `idempotency_effects` y `task_attempts`;
- `outbox_progress`, `outbox_results` y `pending_uploads`;
- `sync_state` y `quarantine`.

SQLite guarda IDs, generaciones, fingerprints y referencias opacas al
SecretStore, nunca enrollment tokens ni credential secrets.

## Durabilidad

Cada conexión activa `foreign_keys`, WAL, `busy_timeout` y `synchronous=FULL`.
La base tiene `application_id` propio y `user_version=1`. Claims e idempotencia
usan `BEGIN IMMEDIATE`; las transiciones usan compare-and-set.

Las migraciones son forward-only y se verifican por SHA-256. Antes de migrar se
crea un backup mediante SQLite backup API y se ejecuta `quick_check` sobre la
copia. Si la migración falla, el archivo fallido se preserva y se restaura el
backup. Un checksum distinto bloquea el inicio.

Cada payload durable conserva su hash. Una fila cuyo JSON o hash no coincida se
marca `rejected`, se copia a `quarantine` y no se ejecuta. La corrupción física
requiere restaurar el último backup verificado.
