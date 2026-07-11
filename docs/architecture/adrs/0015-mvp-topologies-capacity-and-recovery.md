# ADR-0015: MVP topologies, capacity and recovery

## Status

Accepted

## Context

El producto comienza en una estación Windows 11 con Docker Desktop y WSL2,
pero debe crecer hacia hosts Linux, macOS y cloud sin cambiar dominio ni
contratos. También debe separar tráfico y captura del control plane cuando la
carga o la ubicación del laboratorio lo requieran.

La arquitectura necesita supuestos cuantitativos para evitar un diseño sin
límites, sin presentar estimaciones iniciales como SLA o capacidad demostrada.
El MVP no tendrá alta disponibilidad.

## Decision

Se documentan tres topologías compatibles con los mismos límites de dominio:

1. **Single server:** servicios de control, worker, PostgreSQL, Redis, artifact
   store local y tráfico de laboratorio pueden compartir un host de desarrollo,
   con separación lógica y de credenciales.
2. **Server plus Traffic Nodes:** control y persistencia permanecen en el
   servidor; los Traffic Nodes autorizados anuncian capacidad y atienden sólo
   reservas válidas.
3. **Distributed roles:** API, workers, artifact store, Traffic Nodes, Capture
   Nodes e integration adapters pueden residir en hosts o redes separados. La
   distribución no implica failover ni alta disponibilidad en el MVP.

Los servicios de servidor serán Linux OCI y no dependerán de rutas, servicios o
APIs exclusivas de Windows. `C:\Dev` sólo identifica el checkout local actual.

Los supuestos iniciales de capacidad son:

- Hasta 500 agentes registrados.
- Hasta 100 agentes online simultáneamente.
- Hasta 25 pruebas de tráfico concurrentes.
- Hasta 10 campañas concurrentes.
- Telemetría cada 5 segundos durante pruebas.
- Telemetría cada 30 a 60 segundos fuera de pruebas.
- Retención detallada de 30 días.
- Retención agregada de 12 meses.

Estos valores son hipótesis de planificación y límites iniciales de política,
no resultados de benchmark. Deberán validarse con tamaños de muestra,
cardinalidad, bitrates, duración de campañas, artefactos, índices y patrón real
de concurrencia.

El MVP adopta un RPO inicial de 24 horas y un RTO inicial de 4 horas como
objetivos provisionales sujetos a revisión. No son SLA demostrados. Backup,
restore y reconciliación deben probarse antes de aceptar o endurecer esos
objetivos.

PostgreSQL conserva verdad transaccional; Redis coordina; los agentes mantienen
persistencia local; artifact storage se abstrae entre filesystem y S3/MinIO.
Una falla de Redis debe poder reconciliarse sin redefinir la historia de tareas
y resultados.

La primera implementación funcional priorizará servidor, frontend, agente
simulado, Windows y Linux. Android e iOS permanecen en contratos y arquitectura
sin afirmar implementación disponible.

## Consequences

- El MVP puede operar con complejidad inicial acotada, aceptando puntos únicos
  de falla explícitos.
- Traffic Nodes permiten separar carga de red antes de introducir HA.
- Roles distribuidos requieren TLS, identidad, autorización y observabilidad
  entre redes.
- Los objetivos de escala y recuperación pueden cambiar después de medir.
- La retención y los PCAP pueden dominar almacenamiento antes que la telemetría
  estructurada.
- La topología local no puede filtrarse a contratos ni rutas persistidas.

## Alternatives considered

- **Exigir HA desde el MVP:** descartado por complejidad operativa y falta de
  mediciones, sin impedir una evolución futura.
- **Ejecutar siempre tráfico en el servidor de control:** descartado porque
  mezcla recursos, ubicación y riesgo del data plane con el control plane.
- **Adoptar Kubernetes como requisito de arquitectura:** descartado porque una
  plataforma de orquestación no sustituye límites de dominio, recovery ni
  contratos portables.
- **No registrar supuestos cuantitativos:** descartado porque impediría detectar
  cuándo revisar la arquitectura.
- **Tratar RPO/RTO como compromiso definitivo:** descartado porque todavía no
  existen pruebas de backup, restore ni carga.

## Deferred decisions

- Compose, imágenes, redes, volúmenes y configuración ejecutable de Fase 02.
- Sizing medido, índices, particionamiento y política de autoscaling.
- Backup, restore, disaster recovery y eventual arquitectura HA.
- Backend físico de telemetría y resolución de agregaciones.
- Retención diferenciada de PCAP, auditoría y artefactos grandes.
- Topologías cloud/Kubernetes y distribución geográfica.
- Revisión de RPO/RTO basada en criticidad y pruebas operativas.

## References

- [AGENTS.md](../../../AGENTS.md)
- [Deployment topologies](../deployment-topologies.md)
- [Quality attributes and assumptions](../quality-attributes-and-assumptions.md)
- [ADR-0001: Technology stack and portable OCI deployment](0001-technology-stack-and-portable-oci-deployment.md)
- [ADR-0006: Persistent execution queue](0006-persistent-execution-queue-and-worker-abstraction.md)
- [ADR-0007: Transactional, local and artifact storage](0007-transactional-local-and-artifact-storage.md)
