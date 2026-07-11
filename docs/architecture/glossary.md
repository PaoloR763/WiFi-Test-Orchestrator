# Glosario

## Términos del dominio

### Agent

Software identificado individualmente que publica capabilities y recupera
tareas por HTTPS. Puede ejecutarse en Windows, Linux, Android o iOS.

### Agent Protocol

Familia versionada de interacciones entre agente y servidor. Baseline
conceptual: `1.0.0`.

### Artifact

Evidencia asociada a una ejecución, como logs, JSON crudo, CSV, reporte o
PCAP/PCAPNG. Sus bytes viven detrás del artifact store y conservan hash.

### Availability

Información que indica si una métrica pudo obtenerse. Su vocabulario normativo
se definirá posteriormente.

### Capability

Intención funcional versionada que un agente puede implementar bajo
determinadas condiciones. No identifica una herramienta concreta.

### Capability manifest

Snapshot publicado por un agente con dimensiones de soporte, implementación,
permisos, interacción, background, provider y límites.

### Capture Node

Nodo Linux especializado y autorizado para captura IP o, con hardware y driver
adecuados, captura IEEE 802.11 en monitor mode.

### Confidence

Calidad o confiabilidad declarada de una medición según fuente y método. No se
congela todavía una escala.

### Control plane

Plano de usuarios, inventario, campañas, scheduling, políticas, reservas y
auditoría.

### Data plane

Flujo de tráfico sintético de prueba entre endpoints y destinos autorizados.

### Effective limit

Límite concreto aplicado a una ejecución después de intersectar perfil,
política, agente, provider, nodo y reserva.

### Idempotency key

Identificador que permite reconocer reintentos de una misma operación y evitar
duplicar efectos.

### Lease

Asignación temporal de una tarea a un agente o worker. Se mantiene separada de
la tarea inmutable.

### Metric envelope

Representación conceptual formada por `value`, `unit`, `source`,
`availability`, `confidence` y `reason`.

### Plugin

Extensión registrada que implementa una o más interfaces y capabilities bajo
allowlist y cadena de confianza.

### Provider

Implementación concreta de una capability. iperf3 es un provider de tráfico,
no una capability.

### Reason

Explicación de indisponibilidad, restricción o decisión operativa. Es el único
campo conceptual adoptado para ese propósito.

### Reservation

Autorización emitida por el servidor que liga una ejecución de tráfico a un
agente, destino, protocolo, ventana y límites efectivos.

### RPO

Objetivo de punto de recuperación. El valor inicial de 24 horas es provisional.

### RTO

Objetivo de tiempo de recuperación. El valor inicial de 4 horas es provisional.

### Source

Procedencia de una medición: por ejemplo API del sistema operativo, contador
de interfaz, probe activo, captura IP, captura 802.11 o infraestructura.

### Task

Descripción validada e inmutable de trabajo permitido para un agente.

### Telemetry plane

Plano de muestras, eventos, availability y metadata de medición.

### Traffic Node

Servidor de prueba autorizado que anuncia capacidad y acepta tráfico sólo bajo
una reserva válida.

### Trust store

Conjunto administrado de identidades de firma confiables y su estado de
revocación. Su representación se define más adelante.

## Comparabilidad

### Equivalent

Métodos suficientemente alineados en provider, versión, protocolo, dirección,
parámetros, fuente y contexto para una comparación directa declarada.

### Approximate

Métodos relacionados pero con diferencias conocidas que deben acompañar el
resultado.

### Not comparable

Métodos o fuentes cuya diferencia impide una comparación válida.

Estos nombres son categorías documentales iniciales; sus valores normativos se
definirán con los contratos.
