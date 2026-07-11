# ADR-0002: Domain and plane boundaries

## Status

Accepted

## Context

WiFi Test Orchestrator combina administración, scheduling, ejecución de tráfico,
telemetría, artefactos e integraciones con infraestructura. Si esos flujos
comparten responsabilidades implícitas, una operación de prueba puede eludir
políticas, una captura puede mezclarse con datos transaccionales o un adapter
externo puede contaminar el dominio central.

La separación requerida es lógica y contractual. No obliga a desplegar un
microservicio por plano durante el MVP, pero debe seguir siendo visible aun si
varios componentes se empaquetan juntos.

## Decision

La arquitectura se divide en cinco planos con ownership explícito:

| Plane | Responsabilidades | Datos principales | Límites |
| --- | --- | --- | --- |
| `control plane` | Usuarios, RBAC, agentes, inventario, casos, suites, planes, campañas, scheduling, políticas, reservas y auditoría | Estado transaccional, configuración y decisiones de autorización | Autoriza trabajo; no transporta tráfico de prueba ni almacena blobs grandes inline |
| `data plane` | Tráfico sintético entre endpoints y servidores de prueba autorizados | Flujos TCP/UDP/HTTP y metadatos de ejecución | Sólo opera con destino y límites efectivos autorizados; no admite shell remoto ni destinos arbitrarios |
| `telemetry plane` | Muestras, eventos, availability, calidad y contexto de medición | Series temporales y eventos correlacionados | Conserva source, confidence y reason; no inventa datos ausentes |
| `artifact plane` | Ingesta, integridad, retención y acceso a logs, PCAP/PCAPNG, JSON crudo, CSV y reportes | Objetos, hashes, metadata y referencias | Los blobs viven detrás del artifact store; PostgreSQL conserva metadata y trazabilidad |
| `integration plane` | Adapters de AP, gateway, ONT, controller, SNMP, TR-181/USP y APIs externas | Lecturas, snapshots y cambios de infraestructura | Todo cambio requiere permisos específicos, snapshot previo, validación y rollback |

PostgreSQL mantiene la verdad transaccional del control plane y las referencias
necesarias para correlacionar los demás planos. Redis coordina trabajo efímero,
locks, rate limits y cola, pero no reemplaza el registro transaccional e
histórico. El almacenamiento físico de artefactos queda detrás de una interfaz
portable.

Los cruces entre planos usarán contratos explícitos y versionados. Cada flujo
propagará las identidades y datos de correlación necesarios para relacionar
agente, campaña, ejecución, task, reserva, muestra y artefacto sin compartir
modelos internos por accidente.

Un agente participa en varios planos, pero mantiene adaptadores separados:
recupera control por HTTPS, ejecuta el data plane hacia endpoints autorizados,
publica telemetría y entrega artefactos. Esa participación no le otorga acceso
general a la infraestructura ni capacidad de ejecutar comandos arbitrarios.

La telemetría distinguirá, como mínimo, datos del sistema operativo, contadores
de interfaz, captura IP, captura IEEE 802.11 y telemetría de infraestructura. La
comparación declarará si los métodos son equivalentes, aproximados o no
comparables. Un endpoint no se modelará como observador de todas las tramas de
terceros.

Las topologías de servidor único, servidor con traffic nodes y deployment
distribuido preservarán estos mismos límites. Distribuir roles no cambia la
autoridad del control plane ni permite que el data plane eluda una reserva.

## Consequences

- Es posible comenzar con un modular monolith y extraer componentes después sin
  redefinir el dominio.
- Cada dato tiene owner, política de acceso, retención y mecanismo de integridad
  identificables.
- Los adapters externos y providers de pruebas pueden evolucionar sin exponer
  sus modelos internos al núcleo.
- La correlación entre planos exige identificadores consistentes y manejo
  cuidadoso de fallas parciales.
- El artifact plane y el telemetry plane pueden escalar de manera diferente al
  estado transaccional.
- La separación lógica agrega interfaces y validaciones incluso cuando los
  componentes comparten proceso o deployment.

## Alternatives considered

- **Separar sólo por tecnología o repositorio:** descartado porque no aclara
  autoridad, datos ni controles de seguridad.
- **Modelo de datos compartido sin ownership por plano:** descartado porque
  acopla providers, ingestión y scheduling y dificulta auditoría.
- **Encaminar todo el tráfico de prueba a través de la API central:** descartado
  por escalabilidad, aislamiento y mezcla del control plane con el data plane.
- **Permitir acceso directo de plugins a cualquier store o adapter:** descartado
  porque eludiría validación, allowlists y límites del dominio.

## Deferred decisions

- Límites de módulos y procesos concretos dentro del backend inicial.
- Event bus, topics, particiones y formatos de eventos entre planos.
- Estrategia física de almacenamiento y agregación de series temporales.
- Catálogo final de adapters de infraestructura y sus permisos.
- Políticas detalladas de retención para PCAP y otros artefactos sensibles.
- Mecanismos concretos de auditoría inmutable y verificación de hashes.

## References

- [AGENTS.md, secciones 4, 6 y 7](../../../AGENTS.md)
- [ADR-0001: Technology stack and portable OCI deployment](0001-technology-stack-and-portable-oci-deployment.md)
- [ADR-0003: Contract versioning and compatibility](0003-contract-versioning-and-compatibility.md)
- [ADR-0005: Outbound task delivery, leases and idempotency](0005-outbound-task-delivery-leases-and-idempotency.md)
