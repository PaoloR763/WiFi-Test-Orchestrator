# ADR-0011: Metric envelope, null semantics and comparability

## Status

Accepted

## Context

Las métricas provendrán de sistemas operativos, contadores de interfaz, capturas IP, capturas IEEE 802.11, proveedores de tráfico e infraestructura de red. Esas fuentes no observan lo mismo ni ofrecen igual precisión. En particular, las restricciones de Windows, Linux, Android e iOS impiden asumir paridad y una ausencia de dato no puede interpretarse como una medición de cero.

Los resultados también deberán seguir siendo interpretables cuando cambien el hardware, firmware, driver, sistema operativo, proveedor, método o threshold. Un valor escalar aislado no conserva suficiente evidencia para esa comparación y favorece agregaciones técnicamente inválidas.

## Decision

Toda métrica persistida o intercambiada usará un sobre conceptual con los campos obligatorios `value`, `unit`, `source`, `availability`, `confidence` y `reason`.

- `value` contiene el valor medido o `null`. `null` significa que no hay un valor utilizable para esa observación; nunca significa cero y no se convertirá a cero durante ingestión, agregación, evaluación de thresholds ni presentación.
- `unit` declara la unidad independientemente del nombre de la métrica. Las magnitudes adimensionales usarán una unidad explícita definida por el contrato.
- `source` identifica el plano, productor, proveedor, método y versión necesarios para distinguir, por ejemplo, telemetría del SO, contador de interfaz, captura IP, captura 802.11 o infraestructura.
- `availability` expresa el estado de disponibilidad de la observación y no contiene explicaciones libres.
- `confidence` expresa la calidad atribuible a esa observación según una escala controlada y versionada.
- `reason` es el único campo conceptual para explicar indisponibilidad, condicionamiento o degradación. No se creará otro campo con la misma semántica. La forma de representar una explicación aplicable o no aplicable se definirá en el contrato posterior.

Una métrica con `value: null` deberá conservar `unit`, `source`, `availability`, `confidence` y un `reason` coherente. Una métrica disponible con valor numérico cero deberá conservar `value: 0` y un estado de disponibilidad que indique que fue observada; de ese modo cero y ausencia permanecen distinguibles.

Las comparaciones entre ejecuciones declararán una relación de método equivalente, aproximada o no comparable. Esa evaluación considerará, como mínimo, identidad y versión de la métrica, unidad, fuente, proveedor, método, plataforma y contexto de ejecución. Las agregaciones no mezclarán silenciosamente mediciones no comparables. Las comparaciones aproximadas mostrarán su limitación y no se presentarán como equivalentes.

Cada ejecución conservará snapshots inmutables de parámetros, thresholds, manifests, proveedor, método y versiones. Un cambio posterior de threshold, plugin o regla de comparabilidad no alterará el significado histórico del resultado original.

## Consequences

- Los payloads y el almacenamiento serán mayores que con valores escalares, pero cada dato tendrá procedencia y semántica auditables.
- Los productores de todas las plataformas deberán emitir el mismo sobre aunque una medición no esté disponible.
- La interfaz deberá representar ausencia, cero, baja confianza y no comparabilidad como estados distintos.
- Los motores de agregación y thresholds deberán operar sobre disponibilidad y comparabilidad antes de calcular resultados.
- Los contratos y golden vectors deberán probar explícitamente cero, `null`, unidad incorrecta, razón ausente y métodos no comparables.

## Alternatives considered

- Usar escalares y un mapa global de disponibilidad. Se descartó porque permite inconsistencias entre valor, unidad y estado, y pierde procedencia por métrica.
- Convertir valores ausentes a cero. Se descartó porque inventa mediciones y altera promedios, percentiles y thresholds.
- Definir un resultado diferente por plataforma. Se descartó porque fragmenta contratos y traslada al consumidor la reconciliación semántica.
- Considerar comparables todas las métricas con el mismo nombre. Se descartó porque ignora diferencias de método y visibilidad entre plataformas y planos.

## Deferred decisions

- El catálogo completo de códigos para `availability`, `confidence` y `reason`.
- La sintaxis normativa de unidades y la adopción de un estándar externo específico.
- Las reglas estadísticas particulares para cada familia de métricas y tamaño mínimo de muestra.
- La representación exacta en OpenAPI y JSON Schema, que deberá respetar esta semántica en la versión de schema 1.0.0.

## References

- [AGENTS.md](../../../AGENTS.md)
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md)
- [ADR-0003: Contract versioning and compatibility](0003-contract-versioning-and-compatibility.md)
- [Capability matrix](../capability-matrix.md)
