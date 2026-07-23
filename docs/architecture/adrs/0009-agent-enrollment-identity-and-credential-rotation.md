# ADR-0009: Enrolamiento, identidad y rotación de credenciales de agentes

## Status

Accepted

## Context

Cada agente necesita autenticarse individualmente para recuperar tareas, publicar telemetría y cargar resultados o artefactos. Una credencial compartida por una flota impide revocar un solo dispositivo, atribuir acciones y limitar el impacto de una filtración. El bootstrap también debe impedir que un token capturado se reutilice para registrar identidades arbitrarias.

La primera versión debe ser operable en Windows, Linux, Android e iOS sin exigir una PKI de cliente completa, pero la identidad lógica no debe quedar ligada para siempre a un bearer token ni impedir una evolución futura a mTLS.

## Decision

- El enrolamiento se iniciará con un token de un solo uso creado por una identidad humana o de automatización con permiso específico. El token tendrá alcance y vigencia limitados y nunca se usará como credencial operativa del agente.
- El agente iniciará el enrolamiento mediante HTTPS, validará la identidad del servidor y enviará el token junto con la información mínima necesaria de la instalación y plataforma.
- El servidor validará y consumirá el token atómicamente al crear una identidad estable de agente. Una repetición del mismo intento podrá resolverse de forma idempotente sin volver reutilizable el token ni crear agentes duplicados.
- Cada instalación recibirá credenciales individuales, rotables y revocables, asociadas a su `agent_id` y al rol de mínimo privilegio `Agent`. Las credenciales de dos agentes no serán intercambiables ni se compartirán por imagen de instalación.
- La identidad lógica del agente, su método de autenticación y sus credenciales se modelarán por separado. Esta separación permitirá incorporar mTLS y certificados de cliente sin cambiar el `agent_id` ni la semántica de tareas, capabilities o resultados.
- La rotación normal se solicitará por HTTPS autenticado con la credencial vigente. El protocolo permitirá activar una credencial nueva y retirar la anterior sin una ventana indefinida de credenciales válidas; cada transición será auditada.
- El servidor podrá revocar de inmediato una credencial o identidad y rechazará nuevas recuperaciones, renovaciones de lease y cargas asociadas. La pérdida de todas las credenciales requerirá un nuevo bootstrap autorizado, no un fallback compartido.
- Las credenciales se guardarán mediante el secure storage apropiado de cada plataforma: Keychain en iOS, Android Keystore en Android y un adapter de almacenamiento seguro del sistema en Windows/Linux. Los detalles de plataforma permanecerán detrás de una interfaz común.
- Tokens y credenciales se redactarán en logs, errores, auditoría visible, telemetría, reportes y artefactos. La observabilidad registrará identificadores y eventos de lifecycle, no material secreto.
- Los tokens de FCM/APNs, cookies de usuarios y credenciales de infraestructura externa no podrán autenticar a un agente.
- Todas las operaciones posteriores al bootstrap usarán TLS; no habrá modo de producción con transporte en claro.

### Aclaración Android — Fase 08 / C05

La decisión histórica de “guardar credenciales mediante Android Keystore” no
significa almacenar directamente un bearer credential recuperable dentro de
Keystore. En Android, Keystore conserva la clave criptográfica de la aplicación.
C05 usa esa clave para cifrar la credential en memoria mediante AES-256-GCM y
produce un envelope autenticado; no lo persiste ni afirma enrolamiento durable.

C06 incorporará Room v2 y almacenará el envelope completo —sealed credential,
nonce/IV, alias real, versión criptográfica, identidad y metadata requerida—,
nunca el plaintext. Sólo después de completar y validar esa coordinación
transaccional podrá representarse enrolamiento durable. Esta aclaración es
específica del mecanismo Android v1 y no cierra las decisiones históricas sobre
rotación multiplataforma, proof-of-possession o mTLS.

## Consequences

- Es posible revocar, rotar y auditar cada agente sin afectar a toda la flota.
- Una imagen clonada no puede reutilizar legítimamente la misma credencial; el instalador y los runbooks deberán contemplar identidades por instalación.
- El servidor necesita estados explícitos de identidad y credencial, endpoints de lifecycle, rate limits y auditoría inmutable.
- La recuperación ante credenciales perdidas requiere intervención autorizada y puede dejar temporalmente al agente offline.
- Los adapters de secure storage deben manejar diferencias entre servicios desktop y aplicaciones móviles.
- La evolución a mTLS agrega operación de CA y certificados, pero no obliga a rediseñar el dominio.

## Alternatives considered

- **API key compartida por laboratorio o flota:** se descarta porque impide atribución y revocación individual.
- **Token de enrolamiento permanente y reutilizable:** se descarta porque convierte el bootstrap en una credencial maestra difícil de contener.
- **Usar credenciales de un usuario humano en el agente:** se descarta porque mezcla roles, lifecycle y permisos.
- **Exigir mTLS completo desde el MVP:** se posterga para reducir complejidad operativa inicial, preservando una ruta de migración explícita.
- **Usar el token push como identidad:** se descarta porque pertenece a un tercero, puede rotar sin relación con la confianza y sólo sirve para delivery best-effort.

## Deferred decisions

- Formato de credenciales iniciales y protocolo exacto de proof-of-possession.
- Algoritmos criptográficos, longitudes, suites TLS y mecanismo de firma.
- Duración concreta de tokens, credenciales y ventanas de superposición durante rotación.
- Topología de CA, emisión, renovación y rollout de mTLS.
- Attestation de hardware o plataforma y políticas para instalaciones clonadas.
- Procedimiento UX y administrativo para aprobación, recuperación y transferencia de ownership.

## References

- [AGENTS.md](../../../AGENTS.md), secciones 3, 6 y 9.
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md).
- [ADR-0008: Lifecycle móvil y push sólo como aviso](0008-mobile-lifecycle-and-notification-only-push.md).
