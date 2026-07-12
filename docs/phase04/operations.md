# Runbook, seguridad, migración y rollback

## Claves, RBAC y auditoría

Genere `.env` con scripts Bash/PowerShell. HMAC de enrollment, HMAC de
credential y AEAD de replay son independientes de JWT, rate limit y auditoría.
Settings rechaza ausentes, cortas, placeholders o reutilizadas. No publique
`docker compose config`, porque expande secretos.

Permisos sin wildcard cubren enrollment tokens, agents, credentials,
revocation, manifests y protocol inspection; seeds son idempotentes y no existe
rol humano `agent`. AuditLog usa `actor_id` para usuario y `actor_agent_id` para
agente, checks coherentes, trigger append-only y rol runtime sin UPDATE/DELETE.
Se auditan creación/revocación, enrolamiento/recovery, rotación/activación,
replays, conflictos, incompatibilidad y rechazos conocidos. Sanitización elimina
Authorization, cookies, nonces, secrets, ciphertext y HMAC completo.

## Límites

| Payload | Máximo |
|---|---:|
| enrollment / rotation | 32 KiB |
| heartbeat / presence / progress | 64 KiB |
| CapabilityManifest / TaskEnvelope | 256 KiB |
| ArtifactManifest | 64 KiB |
| TestResult provisional | 1 MiB |

Profundidad JSON máxima 16; arrays/objetos generales 128; providers 8. El
middleware corta bodies grandes antes del parseo. No acepta bytes de artifact.

TLS es obligatorio fuera de desarrollo; mTLS/PKI queda futuro. Redis es
obligatorio para replay y falla cerrado. Comprometer PostgreSQL y la clave AEAD
dentro de 15 minutos permite recuperar un secreto en replay. No hay scheduler,
leases, traffic engine, capture/replay, uploads, FCM/APNs ni plugins.

## Persistencia y migración

`20260712_0004` extiende Device, Agent, Capability, EnrollmentToken y AuditLog;
agrega AgentCredential, AgentCredentialRotation, CapabilityManifest,
AgentPresence, IdempotencyRecord y SecretReplay. Usa UUID, TIMESTAMPTZ, FKs con
ON DELETE, checks nombrados, optimistic locking e índices parciales active/pending.

Validación desechable:

```sh
sh scripts/dev.sh test-integration
```

Prueba upgrade, downgrade, re-upgrade, PostgreSQL/Redis real, `alembic check` y
cleanup de contenedores/redes/volúmenes.

Rollback recomendado: conservar schema aditivo. `alembic downgrade
20260712_0003` elimina credentials, presence, manifests, idempotencia y replay;
es destructivo y requiere backup/restauración probada. Agentes de Fase 04 deben
reenrolarse luego de volver a subir.

Para diagnóstico use correlation ID, código ErrorEnvelope y auditoría. Nunca
copie headers de auth ni `.env` a tickets. `dependency_unavailable` en agent auth
suele significar que Redis no pudo reservar nonce.
