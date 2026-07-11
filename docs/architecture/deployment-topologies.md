# Topologías de deployment

## Principios

- Los servicios de servidor son contenedores Linux OCI.
- Windows 11, Docker Desktop y WSL2 son la plataforma inicial de desarrollo,
  no una dependencia del dominio.
- La separación de planos se conserva aunque varios roles compartan host.
- Distribuir roles no implica alta disponibilidad.
- Traffic Nodes, Capture Nodes y destinos deben pertenecer a redes autorizadas.

## Plataformas mínimas

| Rol | Baseline de plataforma |
|---|---|
| Servidor de desarrollo | Windows 11, Docker Desktop y WSL2 |
| Agente Windows | Windows 10 22H2 y Windows 11 |
| Agente Linux | Ubuntu 22.04 o superior como referencia |
| Agente Android | Android 10 / API 29 o superior |
| Agente iOS/iPadOS | iOS 16 o superior |
| Capture Node | Linux especializado, con hardware y driver compatibles |

Todo soporte concreto depende de versión de OS, hardware, driver, permisos,
entitlements y APIs disponibles.

## Topología 1: servidor único

Fuente: [single server topology](diagrams/06-single-server-topology.mmd).

Un host ejecuta frontend, API, scheduler, worker, PostgreSQL, Redis, artifact
store local y, sólo para un laboratorio controlado, un servicio de tráfico.
Los límites lógicos y credenciales de cada servicio se mantienen separados.

Uso previsto:

- Desarrollo local.
- Demostraciones y laboratorios pequeños.
- Validación inicial del producto.

Limitaciones:

- Punto único de falla.
- Competencia de CPU, memoria, disco y red entre control y data plane.
- Un fallo del host detiene todos los roles.
- No es apropiada para capturas 802.11 especializadas.

## Topología 2: servidor más Traffic Nodes

Fuente: [server and traffic nodes topology](diagrams/07-server-and-traffic-nodes-topology.mmd).

El control plane permanece en el servidor principal y los Traffic Nodes
atienden pruebas autorizadas. Cada nodo registra capacidad disponible y sólo
acepta reservas vigentes emitidas por el servidor.

Beneficios:

- Reduce interferencia del tráfico con la API y la base de datos.
- Permite ubicar endpoints de tráfico en diferentes segmentos autorizados.
- Hace explícita la capacidad y concurrencia por nodo.

Controles:

- Allowlist de redes y puertos.
- Reserva vinculada a ejecución, agente, dirección y protocolo.
- Límites efectivos de duración, bitrate, streams, bytes y concurrencia.
- Revalidación ante cambios de resolución o destino.

## Topología 3: roles distribuidos

Fuente: [distributed role topology](diagrams/08-distributed-role-topology.mmd).

API, workers, almacenamiento de artefactos, Traffic Nodes, Capture Nodes y
adapters pueden ubicarse en hosts o redes diferentes. Esta topología define
separación de roles y escalado futuro; el MVP sigue sin HA.

Los flujos entre redes deben usar autenticación, autorización, TLS fuera de
desarrollo, rate limits y observabilidad. Las redes de captura o gestión de
infraestructura no quedan expuestas directamente al frontend.

## Capacidad inicial

| Dimensión | Supuesto inicial |
|---|---:|
| Agentes registrados | 500 |
| Agentes online simultáneos | 100 |
| Pruebas de tráfico concurrentes | 25 |
| Campañas concurrentes | 10 |
| Telemetría durante pruebas | Cada 5 segundos |
| Telemetría fuera de pruebas | Cada 30 a 60 segundos |
| Retención detallada | 30 días |
| Retención agregada | 12 meses |

Como cota de planificación, 100 agentes muestreando cada cinco segundos
producen 20 lotes de agente por segundo. Fuera de pruebas, 100 agentes
producen aproximadamente entre 1,7 y 3,3 lotes por segundo. Esto no es un
dimensionamiento de almacenamiento: faltan tamaño de muestra, compresión,
índices, artefactos y distribución real de carga.

## Disponibilidad y recuperación del MVP

- El MVP no tendrá alta disponibilidad.
- RPO de 24 horas y RTO de 4 horas son objetivos iniciales y provisionales.
- Ambos objetivos deben revisarse cuando existan datos de volumen, criticidad,
  auditoría, duración de campañas y pruebas de restore.
- Backup no equivale a recuperación: se requiere validación periódica de
  restauración en fases operativas posteriores.
- La cola y los leases deben recuperarse sin convertir una reentrega en una
  segunda ejecución efectiva.

## Persistencia por topología

- PostgreSQL conserva el estado transaccional.
- Redis coordina locks, rate limits y entrega, con una estrategia coherente
  con la reconstrucción desde el estado durable.
- El agente usa SQLite para trabajo aceptado, reintentos y upload pendiente.
- El artifact store usa filesystem local en desarrollo y una abstracción
  compatible con S3/MinIO para despliegues posteriores.

## Prioridad de implementación

La primera ola funcional cubre servidor, frontend, agente simulado, Windows y
Linux. Los contratos contemplarán Android e iOS desde el inicio, sin declarar
implementación ni ejecución inmediata donde el lifecycle no lo permita.
