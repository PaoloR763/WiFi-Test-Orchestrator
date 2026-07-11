# Modelo de amenazas

## Estado, alcance y método

Este threat model cubre el baseline arquitectónico `0.1.0`. Utiliza data-flow
diagrams y STRIDE como técnica de descubrimiento, con evaluación cualitativa
provisional. No constituye una certificación ni congela controles
criptográficos.

Fuente visual: [planes and trust boundaries](diagrams/05-plane-and-trust-boundary-flow.mmd).

Incluye:

- Control, data, telemetry, artifact e integration planes.
- Servidor, frontend, agentes, Traffic Nodes y Capture Nodes.
- Plugins/providers, enrolamiento, delivery y almacenamiento.
- Integraciones con infraestructura, FCM y APNs.

Quedan fuera del modelo inicial:

- Redes o dispositivos no autorizados.
- Seguridad física detallada del laboratorio.
- Diseño interno de FCM, APNs, fabricantes de OS o infraestructura.
- Algoritmos y formatos criptográficos finales.

Los terceros se consideran dependencias externas; no se delega en ellos la
autorización de una tarea.

## Objetivos de seguridad

1. Sólo identidades autorizadas crean, reciben o ejecutan tareas.
2. Ningún agente ofrece shell remoto arbitrario.
3. Todo tráfico está ligado a una reserva, destino y límites efectivos.
4. Toda captura o replay está acotada, autorizada y auditable.
5. Plugins y providers se ejecutan sólo tras verificación de confianza.
6. Resultados, telemetría y artefactos conservan integridad y procedencia.
7. Secretos no aparecen en logs, telemetría, errores ni reportes.
8. Una reentrega no produce un segundo efecto real.
9. Cambios de infraestructura tienen snapshot, permiso, validación y rollback.
10. Las restricciones de plataforma se respetan y explican mediante `reason`.

## Activos

| Activo | Sensibilidad | Propiedad a preservar |
|---|---|---|
| Tokens de enrolamiento | Alta | Confidencialidad, un solo uso y expiración |
| Credenciales individuales | Alta | Confidencialidad, autenticidad, rotación y revocación |
| Sesiones y roles RBAC | Alta | Autorización y trazabilidad |
| Tareas e idempotency keys | Alta | Integridad, vigencia y unicidad de efecto |
| Leases y fencing | Alta | Ownership actual y recuperación segura |
| Reservas de tráfico | Alta | Destino, agente, ejecución, límites y autenticidad |
| Capability manifests | Media/alta | Integridad, actualidad y procedencia |
| Resultados y thresholds | Media/alta | Integridad, inmutabilidad histórica y comparabilidad |
| Telemetría y tiempo | Media/alta | Procedencia, orden y calidad temporal |
| Artefactos y PCAP | Alta | Confidencialidad, integridad, retención y acceso |
| Plugins y manifests | Alta | Integridad, origen, compatibilidad y revocación |
| Trust store y claves de firma | Crítica | Integridad, disponibilidad y control de lifecycle |
| Secretos de infraestructura | Crítica | Confidencialidad y uso mínimo |
| Snapshots y rollback | Alta | Integridad y disponibilidad |
| Audit trail | Alta | Integridad, completitud y retención |

## Actores

### Legítimos

- `Administrator`
- `Test Manager`
- `Operator`
- `Viewer`
- Identidad `Agent`
- Agente simulado autorizado
- Traffic Node autorizado
- Capture Node autorizado
- Maintainer o signer de plugins autorizado

### Adversarios o componentes comprometidos

- Usuario externo no autenticado.
- Cuenta de usuario comprometida.
- Insider que excede su función.
- Agente clonado o comprometido.
- Traffic Node o Capture Node comprometido.
- Plugin/provider manipulado o malicioso.
- Atacante en la red entre componentes.
- Servicio externo de notificaciones degradado o abusado.
- Infraestructura administrada comprometida.

## Fronteras de confianza

| Frontera | Riesgo principal | Control base |
|---|---|---|
| Browser ↔ API | Robo de sesión, CSRF, elevación de privilegio | HTTPS, autenticación, RBAC, rate limit y auditoría |
| Agent ↔ server | Suplantación, replay, payload manipulado | HTTPS, credencial individual, expiración e idempotencia |
| API ↔ worker/queue | Doble ejecución, task tampering, desincronización | Estado transaccional, leases, fencing y validación |
| Services ↔ PostgreSQL/Redis | Acceso excesivo o pérdida de coordinación | Credenciales separadas, mínimo privilegio y recovery |
| Artifact service ↔ store | Sustitución, exfiltración o pérdida | Hash, autorización, cifrado futuro y retención |
| Agent core ↔ plugin | Ejecución arbitraria o escalación local | Allowlist, hash, firma, trust store y argumentos registrados |
| Control plane ↔ data plane | Tráfico no autorizado o agotamiento | Reserva, límites concretos, cuotas y destino autorizado |
| Capture Node ↔ monitored network | Captura excesiva o datos sensibles | Interfaz/filtro/tiempo/tamaño, acceso y auditoría |
| Integration adapter ↔ management network | Cambio destructivo o secreto expuesto | Operación tipada, snapshot, permiso y rollback |
| Server ↔ FCM/APNs | Inyección o fuga por push | Aviso sin tarea ni secreto; pull HTTPS como autoridad |
| Trust administration ↔ agents | Signer falso o revocación tardía | Trust store administrado, rotación y fail-closed |

## Data flows sensibles

1. Emisión y consumo de token de enrolamiento.
2. Emisión, almacenamiento, rotación y revocación de credencial.
3. Publicación del capability manifest.
4. Creación de tarea y adquisición de lease.
5. Emisión y validación de reserva de tráfico.
6. Ejecución de provider y control de recursos.
7. Ingesta de telemetría, resultado y artefactos.
8. Distribución, verificación y revocación de plugins.
9. Captura y upload de PCAP.
10. Operación y rollback de infrastructure adapter.

## Registro inicial de amenazas

Los niveles residuales son orientativos y deben revisarse con la
implementación. No representan una aceptación automática.

| ID | STRIDE | Amenaza y activo | Controles arquitectónicos | Riesgo residual o asunto diferido |
|---|---|---|---|---|
| TM-01 | Spoofing / Replay | Robo o reutilización del token de enrolamiento | Un solo uso, consumo atómico, canal autorizado, no logging y auditoría | TTL y prueba de identidad se definen en Fase 04 |
| TM-02 | Spoofing | Clonado de credencial individual | Almacén de plataforma, rotación, revocación y detección de anomalías futura | Tipo de credencial y grace period diferidos |
| TM-03 | Tampering | Alteración de tarea en tránsito o persistencia | HTTPS, schema version, validación estricta, snapshot e integridad transaccional | Wire format y validadores en Fase 04 |
| TM-04 | Repudiation / DoS | Replay o doble ejecución de tarea | Idempotency key, persistencia local, lease separado y fencing | Semántica exacta de ACK/renewal en Fase 10 |
| TM-05 | Tampering | Worker con lease vencido sobrescribe resultado vigente | Ownership actual, fencing y finalización idempotente | Representación de fencing diferida |
| TM-06 | Spoofing / Tampering | Reserva falsificada, reutilizada o aplicada a otro agente | Binding a agente/ejecución/destino, vigencia, autenticidad y revocación | Forma opaca o firmada pendiente |
| TM-07 | Elevation / DoS | Destino arbitrario, DNS rebinding o cambio de IP después de autorizar | Allowlist, resolución controlada, binding y revalidación | Política DNS/IP final en motor de tráfico |
| TM-08 | DoS | Evasión de bitrate, duración, bytes, streams o concurrencia | Intersección de límites, valores efectivos concretos y enforcement en ambos extremos | Valores y precedencia se definen en Fase 12 |
| TM-09 | DoS | Agotamiento de Traffic Node o red de laboratorio | Reserva de capacidad, cuotas, rate limits y máximo de concurrencia | Algoritmo de scheduling diferido |
| TM-10 | Tampering | Capability manifest falso o desactualizado | Identidad de agente, timestamp, versión y snapshot por ejecución | Attestation de dispositivo fuera del baseline |
| TM-11 | Tampering | Telemetría o resultado fabricado por agente comprometido | Procedencia, provider, confidence, correlación y detección futura | Un endpoint comprometido sigue siendo una fuente no confiable absoluta |
| TM-12 | Tampering | Manipulación de reloj para alterar correlación o expiración | UTC, offset, incertidumbre, drift y validación server-side | Fuente y umbrales temporales diferidos |
| TM-13 | Tampering | Artefacto reemplazado o truncado | Hash, tamaño, metadata transaccional y upload idempotente | Cifrado y firma de artefactos se deciden después |
| TM-14 | Information disclosure | Artefactos o PCAP accesibles fuera de RBAC | Autorización por recurso, retención, audit trail y mínimo acceso | Cifrado at-rest y clasificación detallada en Fase 19/23 |
| TM-15 | Information disclosure | Captura demasiado amplia o interfaz/filtro incorrectos | Límites de tiempo/tamaño/interfaz/filtro, preview y control por rol | UX y validación de filtros pendientes |
| TM-16 | Elevation / DoS | Tcpreplay contra red o destino arbitrario | Sólo Capture Node, allowlist, aislamiento, permiso específico y límites | Provider y workflow en Fase 20 |
| TM-17 | Tampering / Elevation | Plugin o binario manipulado | Manifiesto versionado, hash, firma, trust store, allowlist y fail-closed | Formato, algoritmo y canonicalización diferidos |
| TM-18 | Elevation | Plugin usa argumentos para escapar la allowlist | Operaciones tipadas y plantillas de argumentos, sin shell genérico | Sandbox y modelo de proceso por OS pendientes |
| TM-19 | Spoofing | Clave de firma comprometida o signer no autorizado | Trust store administrado, revocación, rotación y auditoría | Distribución y SLA de revocación diferidos |
| TM-20 | Information disclosure | Secreto filtrado en log, error, telemetría o reporte | Redaction, errores estructurados y revisión de sinks | Tests automatizados en Fase 23 |
| TM-21 | Elevation | Rol RBAC ejecuta acción no autorizada | Autorización server-side por acción y recurso, deny by default y auditoría | Matriz de permisos final en Fase 03 |
| TM-22 | Tampering | Cambio de infraestructura sin estado previo o rollback | Snapshot, permiso específico, validación y rollback | Semántica por adapter en Fase 21 |
| TM-23 | DoS / Tampering | Redis pierde estado o diverge de PostgreSQL | PostgreSQL como verdad, reconstrucción y operaciones idempotentes | Persistencia y broker concretos en Fase 02/10 |
| TM-24 | Spoofing | Push falso induce ejecución | Push sin tarea; autenticación y pull HTTPS posterior | Protección del canal depende también del proveedor móvil |
| TM-25 | Repudiation | Acción sensible sin auditoría suficiente | Evento correlacionado con actor, recurso y resultado | Mecanismo de inmutabilidad en Fase 03/23 |
| TM-26 | Information disclosure | Métrica ausente interpretada como cero y oculta una falla | Envelope con availability/confidence/reason; `null` no es cero | Vocabularios en Fase 04 |

## Casos de abuso revisados

### Generación de tráfico

**Caso:** un operador intenta usar una tarea legítima para atacar un destino no
autorizado o superar recursos concedidos.

**Controles:** RBAC, destino allowlisted, reserva ligada a ejecución y agente,
límites efectivos concretos, enforcement en agente y Traffic Node, expiración,
rate limits, cuotas y auditoría. Un valor de límite `null` se resuelve por
herencia; nunca habilita uso ilimitado.

**Riesgo residual:** DNS, NAT, proxy o compromiso de un Traffic Node pueden
cambiar el destino efectivo. La política de resolución y egress debe cerrarse
en la fase del motor de tráfico.

### Captura

**Caso:** un usuario amplía interfaz, filtro, tiempo o tamaño para recolectar
tráfico ajeno.

**Controles:** rol especializado, autorización explícita, límites obligatorios,
filtro validado, aislamiento, hash, acceso restringido y retención. No se
implementa descifrado ni evasión de sandbox.

**Riesgo residual:** aun una captura autorizada puede contener datos sensibles.
Se requiere clasificación, minimización y eliminación verificable.

### Credenciales

**Caso:** un token aparece en logs o una credencial clonada se usa desde otro
dispositivo.

**Controles:** token de un solo uso, consumo atómico, credential store de
plataforma, rotación, revocación, redaction y auditoría.

**Riesgo residual:** no existe todavía attestation de hardware ni un formato de
credencial definitivo. La evolución a mTLS no elimina por sí sola el riesgo de
compromiso del endpoint.

### Plugins

**Caso:** un paquete válido se reemplaza, se instala una versión vulnerable o
la revocación no llega a un agente offline.

**Controles:** hash, firma, allowlist, Plugin API compatible, trust store,
anti-downgrade conceptual y fail-closed antes de cada ejecución.

**Riesgo residual:** canonicalización, distribución del trust store y política
offline deben resolverse antes de habilitar plugins externos.

## Controles por etapa

| Etapa | Prevención | Detección | Respuesta |
|---|---|---|---|
| Enrolamiento | Token de un uso y credencial individual | Intentos fallidos y anomalías | Consumir, revocar y reenrolar |
| Scheduling | RBAC, policy y capability matching | Rechazos y razones | Cancelar campaña o corregir precondición |
| Ejecución | Lease, idempotencia, reserva y allowlist | Heartbeats, métricas y audit events | Expirar, revocar, detener y recuperar |
| Tráfico | Destino y límites efectivos | Contadores en ambos extremos | Cortar flujo y bloquear reserva |
| Captura | Scope mínimo y rol especializado | Tamaño, duración e interfaz observados | Detener, restringir acceso y eliminar según política |
| Plugins | Hash, firma y trust store | Fallas de verificación y versión | Revocar, aislar y evitar nuevas ejecuciones |
| Artefactos | Autorización, hash y retención | Mismatch de integridad | Rechazar, marcar evidencia y reintentar |
| Infraestructura | Snapshot, operación tipada y permiso | Verificación posterior | Rollback y escalamiento operativo |

## Privacidad y retención

- Recolectar sólo métricas y paquetes necesarios para el objetivo autorizado.
- Separar metadata operativa de contenido potencialmente sensible.
- Aplicar acceso por rol, laboratorio, campaña y artefacto.
- No asumir que 30 días de detalle aplica automáticamente a todo PCAP.
- Documentar eliminación, legal hold y agregación antes de producción.
- Excluir secretos y payloads sensibles de notificaciones móviles.

## Riesgos aceptados provisionalmente

- El MVP tiene un único punto de falla y no ofrece HA.
- RPO 24 horas y RTO 4 horas son objetivos provisionales, sujetos a pruebas.
- Un agente comprometido puede falsear observaciones propias; la correlación
  reduce pero no elimina el riesgo.
- La ejecución móvil puede demorarse o no ocurrir por decisión del OS.
- No se promete attestation de hardware en el baseline.

## Revisión y ownership

El modelo debe revisarse al cerrar cada contrato normativo, incorporar un nuevo
provider, habilitar captura/replay, cambiar mínimos de OS, modificar RBAC,
agregar HA/cloud/multi-tenancy o después de un incidente. Cada amenaza debe
obtener owner y evidencia verificable durante la fase que implemente su control.
