# ADR-0003: Contract versioning and compatibility

## Status

Accepted

## Context

El servidor, el frontend y los agentes Windows, Linux, Android e iOS se
implementan con runtimes diferentes y no se actualizan necesariamente al mismo
tiempo. Persisten tareas y resultados que deben conservar su significado aun
cuando cambien thresholds, plugins o providers. Compartir runtime o aceptar JSON
informal no ofrece compatibilidad verificable.

Los JSON presentes en el repositorio son ejemplos ilustrativos. No constituyen
contratos normativos ni deben fijar decisiones pendientes de la fase de
contratos.

## Decision

Se establecen las siguientes líneas base independientes:

| Superficie | Versión inicial |
| --- | --- |
| Producto | `0.1.0` |
| HTTP API | `v1` |
| JSON Schemas | `1.0.0` |
| Agent protocol | `1.0.0` |
| Plugin API | `1.0.0` |

Cada mensaje persistido o intercambiado incluirá `schema_version`. Las versiones
de API, schema, agent protocol, Plugin API, capability, plugin y provider tienen
ciclos distintos y no se inferirán unas de otras.

Los contratos compartidos se describirán mediante OpenAPI, JSON Schema, ejemplos
y contract tests. Esas representaciones se producirán en la fase contractual;
esta decisión fija invariantes y versiones, no sus archivos ni formatos finales.
Los consumidores de Python, TypeScript, Kotlin y Swift validarán los mismos
golden test vectors sin forzar un runtime compartido.

Los cambios serán aditivos por defecto. Un cambio incompatible requerirá una
nueva versión, una estrategia de migración y una ventana de compatibilidad
explícita. No se modificará el significado histórico de datos ya persistidos.
Cada ejecución conservará un snapshot inmutable de parámetros, thresholds,
capability manifests y versiones de plugins/providers relevantes.

Los contratos contemplarán Windows, Linux, Android e iOS desde `1.0.0`. La
prioridad de implementación —servidor, frontend, agente simulado, Windows y
Linux— no autoriza a representar funcionalidades móviles todavía no
implementadas como disponibles.

Toda métrica utilizará un envelope conceptual con `value`, `unit`, `source`,
`availability`, `confidence` y `reason`. `reason` es el único campo para explicar
ausencia, degradación o limitación y no se introducirá un segundo campo con la
misma semántica. Esta fase no fija tipos, valores enumerados, unidades, escalas
ni serialización final para esos campos.

En una métrica, `value: null` nunca significa cero. Debe interpretarse junto con
`availability` y `reason` como ausencia o indisponibilidad de un valor medido. En
un límite solicitado, `null` significa heredar la política aplicable y nunca
significa ilimitado. Antes de ejecutar tráfico, todos los límites efectivos
deben estar resueltos a valores concretos y quedar incluidos en el snapshot de
la ejecución.

Los timestamps se persistirán en UTC. Los datos temporales necesarios para
correlación conservarán además offset, incertidumbre y drift del reloj que los
originó. La representación, precisión y método de estimación se definirán en el
contrato correspondiente.

## Consequences

- Los agentes pueden evolucionar a ritmos diferentes dentro de una ventana de
  compatibilidad declarada.
- Las ejecuciones históricas continúan siendo interpretables después de cambios
  de configuración o provider.
- La generación y validación de contratos requiere disciplina y tests en cuatro
  ecosistemas.
- Los ejemplos ayudan a comprender, pero no pueden usarse como única evidencia
  de conformidad.
- Separar las versiones evita acoplamiento, a costa de negociar y observar más
  dimensiones de compatibilidad.
- El significado de `null` y el envelope de métricas deben aplicarse de forma
  consistente en persistencia, API, UI y reportes.

## Alternatives considered

- **Compartir modelos de runtime entre todas las plataformas:** descartado por
  diferencias de lenguaje, tooling y lifecycle.
- **JSON sin versión ni schema:** descartado porque vuelve ambiguas la evolución
  y la interpretación histórica.
- **Una única versión para producto, protocolo y plugins:** descartado porque
  obliga a actualizaciones coordinadas innecesarias.
- **Tratar ejemplos JSON como especificación normativa:** descartado porque los
  ejemplos no cubren invariantes, casos negativos ni compatibilidad.
- **Usar `null` como cero o como ausencia de límite:** descartado por fidelidad
  técnica y seguridad.

## Deferred decisions

- Estructura de directorios y contenido final de OpenAPI y JSON Schemas.
- Vocabularios cerrados, tipos, formatos, unidades, escalas y representaciones
  serializadas.
- Mecanismo exacto de negociación y rangos de versiones soportados.
- URL, header o media type concreto para expresar la versión HTTP API.
- Duración de la ventana de compatibilidad y política de deprecation.
- Formato de timestamps, precisión y cálculo de offset, incertidumbre y drift.
- Representaciones, algoritmos y campos criptográficos.
- Implementación de golden vectors, generators y contract tests; estas tareas
  corresponden a la Fase 04 o posterior.

## References

- [AGENTS.md, secciones 7, 9 y 10](../../../AGENTS.md)
- [ADR-0002: Domain and plane boundaries](0002-domain-and-plane-boundaries.md)
- [ADR-0004: Capability-driven platform model](0004-capability-driven-platform-model.md)
- [ADR-0005: Outbound task delivery, leases and idempotency](0005-outbound-task-delivery-leases-and-idempotency.md)
