# Atributos de calidad y supuestos

## Supuestos de producto

| Tema | Supuesto inicial | Estado |
|---|---|---|
| Versión inicial | `0.1.0` | Baseline |
| API | `v1` | Baseline de línea pública |
| Schemas | `1.0.0` | Baseline conceptual; no creado |
| Agent Protocol | `1.0.0` | Baseline conceptual; no creado |
| Plugin API | `1.0.0` | Baseline conceptual; no creado |
| Agentes registrados | Hasta 500 | Hipótesis a medir |
| Agentes online | Hasta 100 simultáneos | Hipótesis a medir |
| Tráfico concurrente | Hasta 25 pruebas | Límite inicial de planificación |
| Campañas concurrentes | Hasta 10 | Límite inicial de planificación |
| Retención detallada | 30 días | Objetivo inicial |
| Retención agregada | 12 meses | Objetivo inicial |
| Alta disponibilidad | Fuera del MVP | Decisión aceptada |
| RPO | 24 horas | Objetivo provisional sujeto a revisión |
| RTO | 4 horas | Objetivo provisional sujeto a revisión |

## Seguridad

- Uso exclusivo en redes y dispositivos autorizados.
- Autenticación individual, revocación y rotación por agente.
- RBAC mínimo con `Administrator`, `Test Manager`, `Operator`, `Viewer` y
  `Agent`.
- No existe shell remoto arbitrario.
- Plugins, providers y comandos usan allowlist y cadena de confianza.
- Tráfico requiere reserva, destino autorizado y límites efectivos.
- Capturas y replay están acotados e isolados por rol.
- Cambios de infraestructura requieren snapshot, permiso, validación y
  rollback.
- Secretos no aparecen en logs, excepciones, telemetría ni reportes.

## Portabilidad

- Los servicios de servidor son Linux OCI.
- Los contratos no dependen de rutas, servicios o APIs del host Windows.
- Filesystem y S3/MinIO se esconden detrás de una abstracción de artefactos.
- Celery u otro worker compatible se esconde detrás de una interfaz de
  ejecución.
- Los runtimes de Python, TypeScript, Kotlin y Swift comparten contratos, no
  objetos runtime.

## Fiabilidad

- PostgreSQL es la fuente de verdad transaccional.
- Redis coordina, pero la recuperación no depende de estado efímero sin
  respaldo conceptual.
- Agentes usan persistencia local para tolerar desconexión.
- Leases e idempotencia permiten reentrega sin duplicar efectos.
- Tareas y resultados conservan snapshots inmutables.
- La indisponibilidad se representa explícitamente con `reason`.

## Escalabilidad

La escala inicial permite una instancia lógica del servidor. Los puntos de
extensión deben admitir separar ingesta, workers, artifact storage y Traffic
Nodes. No se promete escalado automático ni HA en el MVP.

Los principales factores aún no medidos son:

- Bytes por lote de telemetría y cardinalidad de métricas.
- Tamaño y frecuencia de logs y PCAP.
- Duración real de pruebas y campañas.
- Cantidad de streams y bitrate por reserva.
- Tiempo de procesamiento y upload en agentes móviles.
- Índices y agregaciones requeridos para comparación histórica.

## Observabilidad y fidelidad

- Correlation IDs atraviesan API, tareas, leases, resultados y artefactos.
- Toda métrica conserva fuente, availability, confidence y reason.
- Tiempo conserva UTC, offset, incertidumbre y drift.
- Un endpoint no se presenta como observador de todas las tramas.
- Roaming desde endpoint se marca como observado o inferido salvo evidencia
  sincronizada de captura.
- Comparaciones declaran método equivalente, aproximado o no comparable.

## Extensibilidad

- Capabilities describen función y no herramienta.
- Providers declaran implementación y versión.
- Interfaces de plugins están versionadas.
- Cambios aditivos son el comportamiento por defecto.
- Cambios incompatibles requieren nueva versión y ventana de compatibilidad.

## Restricciones móviles

- Android depende de permisos runtime, restricciones de Foreground Service,
  throttling de scan y APIs soportadas.
- iOS es foreground-first y no promete scan genérico, monitor mode, daemon
  permanente, RSSI universal ni control arbitrario de perfiles.
- BackgroundTasks, URLSession background, FCM y APNs no garantizan ejecución
  inmediata.

## Disparadores de revisión

Se deben revisar supuestos y ADRs cuando ocurra cualquiera de estos eventos:

- Se supere el 70 % sostenido de una capacidad inicial.
- Una prueba de restore incumpla RPO o RTO.
- Se incorpore HA, multi-tenancy o despliegue cloud productivo.
- Cambie el mínimo de alguna plataforma.
- Se agregue una fuente de captura 802.11 o replay.
- Se defina el contrato normativo de Fase 04.
- Se cambie una interfaz pública o Plugin API.
- Un incidente revele un nuevo caso de abuso.

## Supuestos no resueltos

- Tamaño de muestra y estrategia física de series temporales.
- Alcance de retención para PCAP y artefactos grandes.
- Proveedor inicial de identidad de usuarios.
- Mecanismo y frecuencia de backup/restore.
- Fuentes y umbrales de calidad temporal.
- Distribución y rotación del trust store.
