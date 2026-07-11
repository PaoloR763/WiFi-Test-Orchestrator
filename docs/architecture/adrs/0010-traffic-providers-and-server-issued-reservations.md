# ADR-0010: Providers de tráfico y reservas emitidas por el servidor

## Status

Accepted

## Context

Las pruebas de throughput necesitan generar tráfico controlado sin convertir al agente en una herramienta para alcanzar destinos arbitrarios ni acoplar el producto a un ejecutable. Las plataformas ofrecen implementaciones distintas: iperf3 en Windows/Linux, HTTP y sockets nativos en varias plataformas y providers adicionales en el futuro.

Los perfiles ilustrativos actuales mezclan en algunos casos el nombre de la herramienta con la capability o contienen límites nulos. Esos JSON no son normativos. La arquitectura debe distinguir la intención funcional de la implementación elegida y asegurar que todo tráfico tenga límites efectivos finitos y un destino autorizado.

## Decision

- Las capabilities de tráfico describirán funciones estables. `traffic.tcp.throughput` y `traffic.udp.throughput` serán capabilities funcionales versionadas, independientes del binario o librería que las implemente.
- iperf3 se integrará como un provider con `provider_id` `traffic-provider-iperf3`. En Windows y Linux podrá implementar `traffic.tcp.throughput` y `traffic.udp.throughput` cuando el binario, versión, permisos y política estén disponibles.
- Todos los generators implementarán una interfaz versionada `TrafficGenerator`. El núcleo seleccionará un provider compatible a partir de la capability requerida, su manifest, versión, plataforma, límites y política de fallback explícita.
- Un provider no recibirá autorización para ejecutar comandos arbitrarios. Sus invocaciones, parámetros y binarios deberán estar registrados en la allowlist de plugins y superar validación de manifest, versión, hash, firma, trust store y revocación antes de ejecutarse.
- Cada prueba de tráfico requerirá una reserva emitida por el servidor. El lease de tarea concede ownership temporal de ejecución; la reserva concede por separado autorización y capacidad limitada en el data plane. Para iniciar tráfico deben ser válidos ambos.
- Antes de emitir la reserva, el servidor validará RBAC, políticas, cuotas, concurrencia, capability y límites del agente, provider y traffic node, además de la autorización del destino.
- La reserva vinculará conceptualmente una identidad de reserva con la ejecución y agentes autorizados, capability, dirección, protocolo, endpoints o traffic nodes permitidos, ventana de validez, límites efectivos y controles contra replay. No autorizará destinos o puertos elegidos libremente por el agente o el provider.
- Los destinos serán traffic nodes administrados o endpoints incluidos en una allowlist de redes y dispositivos autorizados. La resolución y validación evitarán que un alias autorizado termine habilitando una dirección fuera de alcance.
- Todo límite solicitado con valor `null` significa “heredar la política aplicable”, nunca “sin límite”. El servidor resolverá la intersección de solicitud, políticas, cuotas, capability, provider, agente y traffic node en límites efectivos concretos.
- Los límites efectivos incluirán, según el método, cotas de duración, bitrate, streams, bytes, concurrencia y destino. Si no puede obtenerse una cota segura y concreta para un recurso aplicable, la reserva no se emitirá.
- El agente y el traffic node validarán la reserva dentro de sus responsabilidades y aplicarán localmente los límites, de modo que una desconexión del control plane no transforme una prueba acotada en tráfico indefinido.
- Cancelación, revocación, expiración o pérdida de capacidad impedirán un nuevo inicio y detendrán de forma segura una ejecución cuando sea posible. El resultado conservará la razón estructurada y distinguirá ausencia de medición de un valor cero.
- Cada ejecución conservará snapshot de perfil, reserva y límites efectivos, además de `provider_id`, versión del provider, método, capability, dirección, protocolo, streams, bitrate solicitado, traffic node, timestamps y contexto de plataforma.
- Otros providers podrán implementar las mismas capabilities sin modificar el núcleo. El fallback entre providers será explícito y quedará registrado para no presentar métodos no equivalentes como comparables.

## Consequences

- Los planes de prueba expresan una intención funcional y no quedan atados a iperf3.
- Incorporar HTTP o sockets nativos no requiere crear una capability diferente sólo por cambiar de implementación.
- Ninguna tarea puede interpretar un límite nulo como ancho de banda, duración o concurrencia ilimitados.
- El control plane debe administrar capacidad, reservas, cuotas, revocación y allowlists de destinos.
- Los traffic nodes y agentes necesitan validación y enforcement local además de la autorización central.
- Comparar resultados exige conservar provider y método y marcar equivalencia, aproximación o no comparabilidad.
- Una caída del servidor no amplía autoridad: los límites efectivos locales siguen siendo obligatorios.

## Alternatives considered

- **Modelar `traffic.iperf3.tcp` como capability principal:** se descarta porque acopla intención y provider y dificulta sustitución o fallback.
- **Acoplar el motor directamente a iperf3:** se descarta porque no cubre todas las plataformas y convierte detalles del proceso en contrato del dominio.
- **Permitir que el agente elija destino y límites:** se descarta por riesgo de abuso, inconsistencias de política y falta de control de capacidad.
- **Interpretar límites nulos como ilimitados:** se descarta porque una omisión de configuración podría producir tráfico no acotado.
- **Usar sólo el lease de tarea como autorización de tráfico:** se descarta porque ownership de ejecución no reserva capacidad ni delimita el data plane.
- **Exponer un remote shell para ejecutar herramientas:** se descarta por seguridad y porque viola el modelo de plugins allowlisted.

## Deferred decisions

- Formato serializado y schema exacto de la reserva.
- TTL y ventanas concretas de validez, renovación o tolerancia temporal.
- Algoritmo criptográfico o mecanismo de protección de integridad y autenticidad de la reserva.
- Algoritmo de selección de traffic nodes, capacity scheduling y tratamiento de NAT.
- Parámetros exactos y schemas de configuración y resultado de cada provider.
- Semántica detallada de pacing UDP, bidirectional traffic y coordinación de múltiples endpoints.

## References

- [AGENTS.md](../../../AGENTS.md), secciones 4, 5, 6, 8 y 9.
- [Prompt 01 - Arquitectura, ADRs y modelo de amenazas](../../../prompts/01_architecture_and_adrs.md).
- [ADR-0006: Cola de ejecución persistente y abstracción de workers](0006-persistent-execution-queue-and-worker-abstraction.md).
- [ADR-0007: Almacenamiento transaccional, local y de artefactos](0007-transactional-local-and-artifact-storage.md).
- Ejemplos JSON de `prompts/examples/`, tratados como ilustrativos y no normativos para esta decisión.
