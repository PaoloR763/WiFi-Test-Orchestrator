# Contratos y versionado

## Alcance

Este documento fija política arquitectónica, no contratos serializados. No se
crean OpenAPI, JSON Schemas, enumeraciones cerradas ni wire formats en Fase 01.

## Registro de baselines

| Superficie | Baseline | Evolución |
|---|---|---|
| Producto | `0.1.0` | SemVer del producto |
| API | `v1` | Versión mayor en la ruta o mecanismo equivalente futuro |
| JSON Schemas | `1.0.0` | SemVer independiente por familia de schema |
| Agent Protocol | `1.0.0` | SemVer y negociación futura |
| Plugin API | `1.0.0` | SemVer y compatibilidad declarada por plugin |
| Capability | Versionada por identidad funcional | Convención final en Fase 04 |

Las versiones son independientes. API `v1` no implica que todos los schemas,
protocolos o plugins compartan el mismo ciclo de release.

## Política de compatibilidad

- Cambios aditivos son el comportamiento por defecto.
- Un campo desconocido debe poder ignorarse cuando el contrato lo autorice.
- Un cambio incompatible requiere nueva versión, migración y ventana de
  compatibilidad.
- Mensajes persistidos o enviados incluyen una versión de schema.
- Una tarea conserva versiones requeridas y parámetros validados.
- Cada ejecución guarda snapshots de parámetros, thresholds, manifests,
  providers y versiones.
- Modificar thresholds o plugins no reinterpreta resultados históricos.
- Los consumidores Python, TypeScript, Kotlin y Swift se validarán mediante
  golden vectors y contract tests en fases posteriores.

No se define todavía la sintaxis de rangos de versión ni el algoritmo de
negociación.

## Modelo conceptual de tarea

Una tarea debe poder expresar, sin fijar forma JSON:

- UUID de tarea y ejecución.
- Tipo y versión.
- Versión de schema.
- Parámetros validados.
- Momento de creación, comienzo permitido y expiración.
- Idempotency key.
- Capabilities funcionales requeridas y sus restricciones de versión.
- Requisitos de foreground o interacción.
- Referencia a políticas, reserva y snapshots.

El lease es un recurso de coordinación separado de la tarea inmutable. TTL,
fencing, ACKs y endpoints se definirán en Fase 04 y Fase 10.

## Modelo conceptual de capability

Una capability se describe mediante dimensiones independientes:

- `technical_support`
- `implementation_status`
- `permission_requirement`
- `user_interaction`
- `background_execution`
- `provider`
- `limitations`

También conserva identidad funcional, versión y `reason` cuando una condición
no puede cumplirse. No se define un estado compuesto que mezcle dimensiones.
El detalle se encuentra en [capability matrix](capability-matrix.md).

Los IDs iniciales son conceptuales y no normativos. Su incorporación a un
schema requerirá revisión en Fase 04.

## Modelo conceptual de métrica

Toda métrica incluye:

- `value`
- `unit`
- `source`
- `availability`
- `confidence`
- `reason`

`reason` es el único nombre para explicar indisponibilidad y no se define un
campo paralelo con la misma semántica. La forma, tipos y vocabularios quedan
diferidos. `value: null` nunca significa cero.

## Modelo conceptual de límites y reservas

- `null` en un límite solicitado significa heredar política.
- Campo ausente y `null` podrán tener semánticas distintas, a definir por el
  contrato.
- Antes de ejecutar tráfico, cada límite efectivo debe ser concreto.
- Los límites efectivos resultan de perfil, política, agente, provider,
  Traffic Node y reserva.
- La reserva vincula agente, ejecución, capability, dirección, protocolo,
  destino, ventana y capacidad autorizada.
- Si no puede verificarse la reserva, la ejecución falla de forma cerrada.

No se decide todavía si la reserva será opaca, firmada o una combinación.

## Modelo conceptual de plugin

Un plugin declara identidad, versión, Plugin API compatible, capabilities
implementadas, plataformas, permisos, límites y schemas que correspondan en
fases futuras. La cadena de confianza incluye allowlist, hash, firma, trust
store y revocación.

El provider inicial de iperf3 se representa conceptualmente como:

```yaml
provider_id: traffic-provider-iperf3
implements:
  - traffic.tcp.throughput
  - traffic.udp.throughput
```

No se fijan formato, algoritmo, canonicalización ni distribución del trust
store en esta fase.

## Ejemplos JSON existentes

Los archivos en `prompts/examples/` son ilustrativos. En particular:

- `schema_version: "2.0"` no reemplaza el baseline `1.0.0`.
- `plugin_api_version: "2.0"` no reemplaza Plugin API `1.0.0`.
- IDs `traffic.iperf3.*` mezclan provider y función y no son canónicos.
- Métricas escalares o availability separada no satisfacen el envelope
  conceptual adoptado.
- Firmas placeholder, hashes nulos y rutas de schemas inexistentes no son
  material de confianza ni contratos.
- Valores de límites, thresholds, UUIDs y timestamps son datos de ejemplo.

Estos archivos no se modifican en Fase 01. Fase 04 decidirá si se reemplazan,
versionan o conservan como fixtures históricos explícitamente etiquetados.

## Decisiones diferidas

| Asunto | Fase primaria |
|---|---|
| OpenAPI y JSON Schemas normativos | 04 |
| Enums, tipos, errores y reason codes | 04 |
| Negociación y rangos de versiones | 04 |
| Forma de tasks, leases y reservas | 04 y 10 |
| TTL, renovación y fencing | 10 |
| Perfil normativo de tráfico | 12 |
| Manifiesto y SDK de plugins | 22 |
| Formatos criptográficos y key lifecycle | 23 |
| Contratos de telemetría y tiempo | 16 |
