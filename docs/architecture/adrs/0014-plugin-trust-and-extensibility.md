# ADR-0014: Plugin trust and extensibility

## Status

Accepted

## Context

La plataforma debe incorporar traffic generators, probes, capture providers,
infrastructure adapters y report renderers sin acoplar el núcleo a cada
herramienta. Esa extensibilidad crea una frontera de ejecución privilegiada:
un plugin manipulado, incompatible o excesivamente permisivo puede ejecutar
procesos, exfiltrar secretos o eludir políticas de tráfico y captura.

Una firma aislada no resuelve identidad, integridad, versión, confianza,
revocación ni downgrade. Tampoco debe transformarse el sistema de plugins en un
shell remoto parametrizable.

## Decision

- Las extensiones se integrarán mediante interfaces versionadas:
  `TestPlugin`, `TrafficGenerator`, `LatencyProbe`, `CaptureProvider`,
  `InfrastructureAdapter` y `ReportRenderer`.
- Plugin API tendrá baseline conceptual `1.0.0`. La forma del SDK, wire format y
  reglas finales de compatibilidad se definirán en fases posteriores.
- Una capability representa intención funcional; un plugin/provider declara
  qué capabilities implementa. La herramienta no forma parte del capability
  ID.
- iperf3 se registra conceptualmente como provider/plugin:

  ```yaml
  provider_id: traffic-provider-iperf3
  implements:
    - traffic.tcp.throughput
    - traffic.udp.throughput
  ```

  Este fragmento no es un manifiesto normativo.
- Cada plugin tendrá un manifiesto versionado que permita relacionar identidad,
  versión, Plugin API compatible, plataformas, capabilities, permisos,
  operaciones, límites, integridad y procedencia. Su estructura final se
  difiere.
- La activación exige allowlist, verificación de hash, firma, trust store y
  revocación. Una falla o ambigüedad se trata de forma cerrada.
- Hash y firma deben cubrir de manera inequívoca el artefacto y la metadata que
  define su comportamiento. Algoritmos, canonicalización y formatos no se
  congelan en esta fase.
- El trust store tendrá lifecycle administrado y distinguirá confianza activa,
  rotación y revocación sin definir todavía su representación.
- Antes de cada ejecución se revalidarán identidad/version del plugin,
  compatibilidad, estado de confianza, capability, operación solicitada y
  límites aplicables.
- Las operaciones y argumentos permitidos estarán registrados. No se expondrá
  un shell genérico, una cadena de comando libre ni expansión arbitraria de
  parámetros.
- Un plugin no obtiene por sí mismo acceso a secretos, filesystem, red,
  interfaces, destinos o privilegios. Cada recurso requiere permiso explícito y
  mínimo.
- Una versión revocada o no permitida no iniciará nuevas ejecuciones. El
  tratamiento de trabajo activo y agentes offline seguirá una política
  posterior que preserve seguridad y trazabilidad.
- Los resultados conservarán plugin/provider ID, versión, método, capabilities
  implementadas y contexto de plataforma.
- Actualizar un plugin no modifica resultados históricos: cada ejecución
  conserva snapshots de manifest, parámetros y versiones.

## Consequences

- Nuevos providers pueden incorporarse sin modificar el dominio central.
- La cadena de distribución de plugins se convierte en un activo crítico.
- El agente necesita verificación fail-closed y un runtime con privilegio
  mínimo por plataforma.
- Revocación y rotación deben llegar a agentes que pueden estar offline.
- La compatibilidad de Plugin API requiere contract tests y fixtures en fases
  posteriores.
- El control de argumentos puede limitar flexibilidad, pero evita convertir un
  plugin legítimo en ejecución arbitraria.

## Alternatives considered

- **Integrar cada herramienta directamente en el núcleo:** descartado por
  acoplamiento, releases coordinadas y superficie de privilegios difusa.
- **Confiar sólo en el nombre o versión declarada:** descartado porque no prueba
  integridad ni procedencia.
- **Verificar sólo un hash sin identidad de signer:** descartado porque no
  establece quién autorizó el artefacto ni permite un trust lifecycle completo.
- **Aceptar cualquier plugin firmado por cualquier clave conocida:** descartado
  porque la confianza debe considerar allowlist, scope y revocación.
- **Permitir comando y argumentos libres:** descartado porque equivale a shell
  remoto arbitrario.

## Deferred decisions

- JSON Schema o formato normativo del manifiesto y paquetes.
- Algoritmos de hash/firma, canonicalización y formato de firma.
- Distribución, rotación, almacenamiento y revocación del trust store.
- Sandbox y aislamiento concreto por Windows, Linux, Android e iOS.
- Política offline, revocation freshness y tratamiento de ejecución activa.
- SDK, tooling, contract tests y proceso de publicación de plugins.
- Reglas exactas de compatibilidad, upgrade, downgrade y rollback.

## References

- [AGENTS.md](../../../AGENTS.md)
- [ADR-0003: Contract versioning and compatibility](0003-contract-versioning-and-compatibility.md)
- [ADR-0004: Capability-driven platform model](0004-capability-driven-platform-model.md)
- [ADR-0010: Traffic providers and server-issued reservations](0010-traffic-providers-and-server-issued-reservations.md)
- [Plugin verification sequence](../diagrams/13-plugin-verification-and-revocation.mmd)
