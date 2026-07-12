# Auditoría y retención

`AuditLog` es independiente de logs operativos. Conserva actor, acción,
recurso, resultado, UTC, correlation ID y metadata sanitizada. Login fallido o
usuario inexistente guarda sólo fingerprints HMAC, nunca el identificador claro.

Metadata usa allowlist, longitudes acotadas y máximo 16 KiB. Se excluyen
passwords, tokens, cookies, hashes, digests, secretos, DSNs y Authorization.

La garantía es exactamente: **append-only para la aplicación y el rol runtime**.
El repositorio no expone update/delete, el rol runtime sólo recibe SELECT/INSERT
y un trigger rechaza UPDATE/DELETE. Esto no declara inmutabilidad frente al
propietario o superusuario de PostgreSQL, que puede alterar schema o controles.

Retención objetivo inicial: 12 meses online. No hay purga automática en Fase 03;
el procedimiento futuro debe ser privilegiado, auditable, compatible con legal
hold y no estar disponible al rol runtime.
