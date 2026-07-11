# ADR-0004: Capability-driven platform model

## Status

Accepted

## Context

Windows, Linux, Android e iOS exponen APIs, permisos y modelos de lifecycle
diferentes. Incluso dentro de una plataforma, el soporte depende de la versión
del sistema operativo, hardware, driver, permisos, entitlements y APIs
disponibles. Un único estado como “supported/conditional/permission required/
user interaction required/unsupported” mezcla causas independientes y produce
scheduling incorrecto.

Los providers también cambian sin cambiar la intención funcional de una prueba.
En particular, iperf3 es una implementación posible de throughput en desktop y
no debe convertirse en el nombre estable que consumen campañas y políticas.

## Decision

Cada agente publicará un capability manifest versionado. Una capability expresa
una intención funcional y tiene identidad y versión independientes del provider
que la implementa.

El modelo y la matriz de capabilities conservarán por separado, como mínimo,
estas dimensiones:

| Dimensión conceptual | Información que debe expresar |
| --- | --- |
| `technical_support` | Si la combinación real de OS/version, hardware, driver y APIs puede realizar la función |
| `implementation_status` | Si la versión instalada del producto contiene una implementación utilizable y su estado de madurez |
| `permission_requirement` | Permisos, roles, privilegios o entitlements necesarios y su disponibilidad actual |
| `user_interaction` | Interacción requerida para preparar, autorizar o ejecutar la operación |
| `background_execution` | Restricciones de foreground/background, duración y lifecycle aplicable |
| `provider` | `provider_id`, versión y método que materializan la función |
| `limitations` | Límites de duración, throughput, tamaño, concurrencia y condiciones ambientales |

No habrá un estado único que colapse esas dimensiones. Términos descriptivos
como `supported`, `unsupported`, `conditional`, `permission_required` o
`user_interaction_required` pueden informar una dimensión o una vista, pero no
reemplazan el modelo multidimensional. Los vocabularios y representaciones
definitivos se fijarán en los contratos posteriores.

Cuando una tarea no pueda ejecutarse, el agente y el servidor explicarán el
resultado `SKIPPED` o `BLOCKED` mediante un único `reason`, según corresponda. La
representación final de esos resultados no se define en este ADR.

La siguiente lista es un catálogo inicial conceptual, no un contrato normativo:

- `wifi.connection.read`
- `wifi.scan`
- `wifi.rssi.read`
- `network.icmp.ping`
- `network.tcp.probe`
- `network.http.probe`
- `traffic.tcp.throughput`
- `traffic.udp.throughput`
- `traffic.http.download`
- `traffic.http.upload`
- `traffic.latency_under_load`
- `capture.ip`
- `capture.ieee80211.monitor`
- `traffic.pcap.replay`
- `execution.background.continuous`

Los nombres, granularidad, versiones y composición de esas capabilities quedan
sujetos a validación y a los contratos de la Fase 04 o posterior.

iperf3 será un provider/plugin con el identificador conceptual
`traffic-provider-iperf3`. Implementará `traffic.tcp.throughput` y
`traffic.udp.throughput` donde la plataforma y sus restricciones lo permitan.
Campañas, casos y policies seleccionarán la intención funcional; la resolución
a un provider respetará capabilities, policy, disponibilidad y compatibilidad.

Todo plugin/provider se admitirá sólo mediante allowlist, manifest versionado,
hash, firma, trust store y revocación. Esta decisión establece la cadena de
confianza como requisito, pero no fija algoritmos, formatos ni distribución de
claves. Un provider no puede ampliar permisos o destinos por declarar una
capability.

La matriz cubrirá Windows 10 22H2/Windows 11, Ubuntu 22.04 o superior, Android
10/API 29 o superior, iOS 16 o superior y el rol Linux Capture Node. Distinguirá
capability contemplada, soporte técnico e implementación disponible. La primera
entrega puede implementar servidor, frontend, agente simulado, Windows y Linux
sin afirmar que Android o iOS ya ejecutan la misma función.

Se respetarán explícitamente las limitaciones móviles. iOS no prometerá scan
genérico, monitor mode, daemon permanente, RSSI universal ni control arbitrario
de perfiles. Android respetará runtime permissions, scan throttling,
restricciones de foreground services y las APIs soportadas de
Suggestion/Specifier.

Los resultados conservarán provider, versión, método y contexto de plataforma,
y declararán si mediciones comparadas son equivalentes, aproximadas o no
comparables. El envelope y la semántica de métricas se definen en ADR-0003.

## Consequences

- El scheduler puede distinguir una imposibilidad técnica de una implementación
  pendiente, un permiso faltante o una restricción de background.
- Agregar o reemplazar providers no obliga a renombrar casos y campañas que
  expresan la misma intención funcional.
- Los manifests son más ricos que un booleano o estado único y requieren
  validación, actualización y observabilidad cuidadosas.
- La UI debe mostrar varias dimensiones y razones sin sugerir falsa paridad.
- El soporte puede cambiar después de una actualización de OS, driver, hardware,
  entitlement, permiso, agent build o provider.
- La selección de provider debe quedar registrada para permitir trazabilidad y
  comparaciones válidas.

## Alternatives considered

- **Un solo estado de capability:** descartado porque mezcla soporte técnico,
  implementación, permisos, interacción y lifecycle.
- **Capabilities con nombres de herramientas, como iperf3:** descartado porque
  acopla el dominio a una implementación intercambiable.
- **Matriz estática sólo por sistema operativo:** descartada porque ignora
  versión, hardware, driver, permisos, entitlements y APIs.
- **Asumir paridad entre desktop y mobile:** descartado porque contradice los
  límites reales de Android e iOS.
- **Codificar todas las diferencias de plataforma en el servidor:** descartado
  porque el agente conoce mejor su estado real y el servidor perdería capacidad
  de extensión.

## Deferred decisions

- JSON Schema, OpenAPI y representación final del capability manifest.
- Vocabularios cerrados, tipos y reglas de combinación de cada dimensión.
- Versiones normativas e IDs definitivos de capabilities.
- Protocolo de negociación, refresh y expiración del manifest.
- Algoritmo de selección y fallback entre providers equivalentes.
- Matriz validada de soporte por combinación de OS, hardware y driver.
- Descubrimiento dinámico, diagnósticos de permisos y UX mobile.
- Algoritmos de firma, formatos de manifest, trust store y revocation data.

## References

- [AGENTS.md, secciones 2, 5, 7 y 8](../../../AGENTS.md)
- [ADR-0003: Contract versioning and compatibility](0003-contract-versioning-and-compatibility.md)
- [ADR-0005: Outbound task delivery, leases and idempotency](0005-outbound-task-delivery-leases-and-idempotency.md)
