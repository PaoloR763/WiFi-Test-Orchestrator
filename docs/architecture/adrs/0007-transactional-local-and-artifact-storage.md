# ADR-0007: Almacenamiento transaccional, local y de artefactos

## Status

Accepted

## Context

La plataforma combina estado transaccional, coordinación efímera, telemetría, colas locales de agentes y artefactos potencialmente grandes o sensibles. Ningún único mecanismo cubre correctamente todos esos usos. En particular, logs, PCAP/PCAPNG, JSON crudo, CSV y reportes no deben forzar a PostgreSQL a actuar como object store, mientras que un filesystem local no ofrece por sí solo integridad transaccional ni portabilidad a S3/MinIO.

Los agentes pueden permanecer desconectados y deben conservar tareas, checkpoints y resultados hasta que el servidor los acepte. Además, una escritura en PostgreSQL y una carga a un object store no pueden confirmarse mediante una transacción ACID común y portable.

## Decision

- PostgreSQL será la fuente de verdad para identidades, inventario, campañas, políticas, tareas, ejecuciones, metadatos de telemetría y artefactos, auditoría y snapshots inmutables de parámetros, thresholds, manifests y versiones.
- Redis contendrá coordinación reconstruible, locks, rate limits, cachés y transporte de cola. Ningún dato de negocio existirá únicamente en Redis.
- Los agentes desktop usarán SQLite y los agentes móviles Room/SQLite para inbox, outbox, checkpoints y resultados pendientes. Cada transición local que deba sobrevivir a un reinicio se confirmará en una transacción antes de anunciarse o eliminar su predecesora.
- Los secretos no se almacenarán como datos ordinarios en SQLite, logs, telemetría ni artefactos. Se usarán los mecanismos seguros de credenciales disponibles en cada sistema operativo detrás de una abstracción de identidad.
- Los artefactos se almacenarán mediante una interfaz `ArtifactStore` con al menos un adapter de filesystem local para desarrollo y adapters compatibles con S3/MinIO. Las rutas físicas y detalles del backend no formarán parte de los contratos públicos.
- PostgreSQL conservará para cada artefacto su identidad, ejecución propietaria, clasificación, media type, tamaño, hash de integridad, estado de disponibilidad, timestamps UTC, política de retención y referencia opaca de almacenamiento.
- La publicación de un artefacto seguirá un flujo recuperable: registrar intención, cargar a una ubicación temporal, verificar tamaño e integridad, finalizar el objeto y marcar disponibles sus metadatos. Fallas parciales se resolverán mediante retry, reconciliación o limpieza de huérfanos; no se usará distributed two-phase commit.
- Los artefactos se tratarán como inmutables una vez publicados. Una corrección crea una nueva identidad y conserva trazabilidad; la eliminación por retención mantiene la auditoría mínima que permita explicar qué existió y por qué se eliminó.
- La telemetría detallada tendrá una retención inicial de 30 días y los agregados una retención de 12 meses. Las políticas distinguirán datos estructurados, artefactos y material sensible como capturas.
- Toda métrica persistida conservará `value`, `unit`, `source`, `availability`, `confidence` y `reason`. Un `value` nulo representa ausencia o indisponibilidad explicada, nunca cero.
- Los timestamps persistidos estarán en UTC y conservarán, cuando corresponda, offset observado, incertidumbre y drift para permitir correlación entre endpoint, infraestructura y captura.
- El diseño inicial de backup y restore tomará como objetivos provisionales un RPO de 24 horas y un RTO de 4 horas para el MVP sin alta disponibilidad. Ambos quedarán sujetos a revisión mediante pruebas de restauración de metadatos y artefactos.

## Consequences

- Cada clase de datos usa un almacenamiento acorde a sus garantías y volumen.
- El servidor puede cambiar de filesystem local a S3/MinIO sin modificar el dominio ni exponer rutas del host Windows.
- La consistencia entre PostgreSQL y el artifact store es eventual y observable; exige estados intermedios, reconciliación y garbage collection.
- Los agentes requieren migraciones y límites de crecimiento para sus bases locales.
- La inmutabilidad, los hashes y la auditoría mejoran reproducibilidad y detección de corrupción, pero incrementan almacenamiento y trabajo operacional.
- La retención detallada y agregada requiere jobs verificables que no alteren la semántica histórica.

## Alternatives considered

- **Guardar todos los binarios en PostgreSQL:** se descarta por costo, crecimiento, backups y acoplamiento de cargas transaccionales con artefactos grandes.
- **Guardar estado de negocio sólo en Redis:** se descarta porque la coordinación efímera no reemplaza una fuente de verdad auditable.
- **Exponer rutas del filesystem en la API:** se descarta por seguridad y por dependencia del deployment.
- **Escrituras independientes sin reconciliación:** se descartan porque dejan objetos huérfanos o metadatos que apuntan a contenido inexistente.
- **Distributed two-phase commit entre base y object store:** se descarta por falta de soporte portable y complejidad desproporcionada.

## Deferred decisions

- Esquema físico de tablas, particionamiento y estrategia de agregación de telemetría.
- Backend y layout definitivo de buckets, prefixes o directorios.
- Algoritmos concretos de hash, cifrado at rest y gestión de claves.
- Umbrales de multipart upload, compresión y deduplicación.
- Plazos diferenciados de retención legal o de laboratorio para PCAP, auditoría y reportes.
- Procedimiento y frecuencia de backup, y revisión de los objetivos provisionales de RPO y RTO con evidencia operativa.

## References

- [AGENTS.md](../../../AGENTS.md), secciones 3, 4, 7, 9, 10 y 12.
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md).
- [ADR-0006: Cola de ejecución persistente y abstracción de workers](0006-persistent-execution-queue-and-worker-abstraction.md).
