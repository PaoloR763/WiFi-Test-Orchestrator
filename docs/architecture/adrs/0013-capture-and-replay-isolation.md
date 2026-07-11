# ADR-0013: Capture and replay isolation

## Status

Accepted

## Context

Captura IP, captura IEEE 802.11 en monitor mode y replay de PCAP tienen
privilegios, visibilidad y riesgos distintos. Un endpoint común no observa todo
el medio inalámbrico ni todas las tramas de terceros. Hardware, driver,
firmware, canal, permisos y APIs determinan qué evidencia puede producirse.

Una captura sin límites puede recolectar datos sensibles o agotar disco y red.
Un replay sin aislamiento puede convertirse en generación de tráfico contra
destinos arbitrarios. Android e iOS no ofrecen paridad con un Capture Node Linux
y no se deben eludir sus sandboxes.

## Decision

- `capture.ip`, `capture.ieee80211.monitor` y `traffic.pcap.replay` son
  capabilities conceptuales distintas y todavía no normativas.
- Toda afirmación de soporte depende de versión de OS, hardware, driver,
  firmware, permisos, entitlements y APIs disponibles. El manifest conserva
  esas condiciones mediante dimensiones separadas.
- La captura IP de un endpoint no se presentará como captura 802.11. La captura
  802.11 requiere un Capture Node Linux especializado, radio y driver
  compatibles, monitor mode autorizado y metadata de fuente.
- Cada tarea de captura tendrá límites efectivos de duración, tamaño, interfaz
  y filtro. Si un límite aplicable no puede resolverse de forma segura, la tarea
  no se inicia.
- No se implementará descifrado, evasión de permisos, bypass de sandbox ni
  adquisición de tráfico fuera del laboratorio y alcance autorizados.
- El filtro se validará antes de activar captura. El provider no podrá ampliar
  interfaz, canal, tamaño, duración ni alcance mediante parámetros libres.
- Los archivos PCAP/PCAPNG se tratarán como artefactos sensibles: upload
  autorizado, hash, metadata, control de acceso, auditoría y retención
  diferenciada.
- Las métricas derivadas conservarán `value`, `unit`, `source`, `availability`,
  `confidence` y `reason`. RSSI por trama de una captura no se confundirá con
  `wifi.rssi.read` del endpoint.
- Roaming observado por un endpoint se declarará observado o inferido. Sólo una
  captura adecuada y sincronizada puede aportar evidencia adicional, sin
  garantizar que haya observado todas las tramas.
- `traffic.pcap.replay` estará excluida de endpoints Windows, Linux comunes,
  Android e iOS. Sólo podrá evaluarse en un Capture Node Linux especializado,
  aislado y explícitamente autorizado.
- Un replay requerirá plugin/provider allowlisted, permiso específico, red e
  interfaz autorizadas, reserva emitida por el servidor y límites efectivos de
  tasa, duración, bytes, concurrencia y destino que correspondan.
- Tcpreplay podrá ser un provider futuro de replay, nunca una capacidad general
  ni un comando libre. Su disponibilidad por defecto será nula hasta que el rol
  y la política especializada estén configurados.
- Captura y replay no se ejecutarán simultáneamente en el mismo recurso si la
  competencia por CPU, disco, radio o red vuelve inválida la medición, salvo que
  un plan validado documente el método y su impacto.

## Consequences

- Los endpoints comunes conservan un modelo de privilegio menor.
- La evidencia de captura queda atribuida a una fuente y método concretos.
- El Capture Node requiere aprovisionamiento, aislamiento, inventario de
  hardware y controles operativos adicionales.
- Los PCAP pueden requerir una retención menor que la telemetría estructurada.
- La comparación entre endpoint, infraestructura y captura necesita calidad
  temporal y no siempre será concluyente.
- Replay exige capacity planning y controles del data plane equivalentes o más
  estrictos que una prueba de tráfico sintético.

## Alternatives considered

- **Ofrecer monitor mode en todos los agentes:** descartado porque las
  plataformas, drivers y permisos no lo soportan de forma uniforme.
- **Tratar captura IP y 802.11 como el mismo método:** descartado porque su
  visibilidad y semántica son diferentes.
- **Permitir replay desde cualquier agente:** descartado por riesgo de abuso y
  falta de aislamiento.
- **Aceptar filtros o interfaces arbitrarios enviados por el usuario:**
  descartado porque eludiría allowlists y límites del laboratorio.
- **Conservar todos los PCAP durante 30 días sin clasificación:** descartado
  porque volumen y sensibilidad requieren política específica.

## Deferred decisions

- Providers concretos, hardware/driver certificados y proceso de
  aprovisionamiento del Capture Node.
- Lenguaje, validación y catálogo allowlisted de filtros de captura.
- Retención, clasificación y cifrado de PCAP/PCAPNG.
- Representación normativa de tareas y resultados de captura/replay.
- Provider de tcpreplay, controles de interfaz y workflow de aprobación.
- Reglas de sincronización y comparabilidad para análisis 802.11.

## References

- [AGENTS.md](../../../AGENTS.md)
- [ADR-0002: Domain and plane boundaries](0002-domain-and-plane-boundaries.md)
- [ADR-0010: Traffic providers and server-issued reservations](0010-traffic-providers-and-server-issued-reservations.md)
- [ADR-0011: Metric envelope and comparability](0011-metric-envelope-null-semantics-and-comparability.md)
- [Threat model](../threat-model.md)
