# Flujos de runtime

## Alcance

Los flujos siguientes fijan invariantes arquitectónicas. No fijan todavía
payloads, enumeraciones cerradas, TTL, formatos criptográficos ni endpoints.

## Enrolamiento y rotación

Fuente: [enrollment and credential rotation](diagrams/09-enrollment-and-credential-rotation.mmd).

1. Un operador autorizado crea un token de enrolamiento de un solo uso.
2. El token se entrega al dispositivo por un canal autorizado.
3. El agente inicia HTTPS y presenta el token junto con información mínima de
   plataforma.
4. El servidor consume el token de forma atómica y registra el agente.
5. El servidor emite credenciales individuales, revocables y rotables.
6. El agente protege la credencial usando el almacén adecuado de la plataforma.
7. Rotación y revocación se auditan. Una credencial anterior sólo puede tener
   una transición controlada y nunca se acepta indefinidamente.
8. La evolución a mTLS se mantiene prevista sin definir todavía certificados,
   perfiles o autoridades finales.

El token no debe aparecer en logs, telemetría, excepciones ni artefactos.

## Recuperación de tarea, lease y ejecución

Fuente: [task lease execution and results](diagrams/10-task-lease-execution-and-results.mmd).

1. El agente consulta trabajo por HTTPS usando su identidad individual.
2. El servidor selecciona tareas no expiradas compatibles con el manifest y
   las políticas actuales.
3. El agente obtiene un lease separado de la tarea.
4. Antes de ejecutar valida tipo, versión, parámetros, expiración,
   idempotency key, capabilities requeridas, plugin allowlisted y reserva.
5. El agente persiste localmente la aceptación antes de iniciar efectos.
6. El lease se renueva mientras la plataforma permita continuar.
7. Telemetría, resultado y artefactos se envían con operaciones idempotentes.
8. La finalización valida ownership y evita que un lease obsoleto sobrescriba
   un intento posterior.

La entrega se diseña para reintentos. La idempotencia debe impedir que una
reentrega produzca un segundo efecto real. Duraciones, fencing y forma exacta
del protocolo se definirán en Fase 04 y Fase 10.

Si faltan capabilities, permisos, foreground o interacción, la ejecución no se
fuerza. El resultado operativo explica la decisión mediante `reason`. La forma
cerrada de estados como `SKIPPED` o `BLOCKED` se difiere al contrato.

## Avisos móviles

Fuente: [mobile notification and task retrieval](diagrams/11-mobile-notification-and-task-retrieval.mmd).

- FCM y APNs sólo indican que podría existir trabajo.
- El aviso no contiene la tarea, secretos, reserva ni parámetros sensibles.
- Tras el aviso, la aplicación intenta recuperar trabajo por HTTPS.
- Un aviso tardío, duplicado o perdido no cambia la fuente de verdad.
- Android utiliza mecanismos de foreground y trabajo diferido permitidos.
- iOS es foreground-first; BackgroundTasks y background URLSession no
  garantizan ejecución inmediata.
- La expiración de una tarea es un resultado esperado y explicable.

## Reserva y ejecución de tráfico

Fuente: [traffic reservation and enforcement](diagrams/12-traffic-reservation-and-enforcement.mmd).

1. El control plane valida usuario, campaña, agente, capability, política y
   capacidad del Traffic Node.
2. El servidor selecciona únicamente un destino autorizado.
3. Perfil, política, límites del agente, provider, reserva y capacidad se
   intersectan para producir límites efectivos concretos.
4. Un límite solicitado `null` hereda la política aplicable; nunca significa
   ilimitado.
5. La reserva queda ligada a la ejecución, agente, dirección, protocolo,
   destino y ventana autorizada.
6. Agente y Traffic Node validan la autorización antes de abrir el data plane.
7. La prueba se detiene al alcanzar cualquier límite efectivo o revocación.
8. Resultado y auditoría conservan la reserva y los límites utilizados.

La representación final de la reserva y el mecanismo de autenticidad quedan
diferidos. La arquitectura exige fail-closed si no se puede verificar.

## Telemetría, resultado y artefactos

- Durante una prueba, la cadencia objetivo es de cinco segundos.
- Fuera de pruebas, la cadencia objetivo es de 30 a 60 segundos.
- Cada métrica contiene conceptualmente `value`, `unit`, `source`,
  `availability`, `confidence` y `reason`.
- `value: null` no equivale a cero.
- Timestamps se expresan en UTC y conservan offset, incertidumbre y drift.
- Resultados preservan provider, versión, método, dirección, protocolo,
  streams, bitrate solicitado, límites efectivos, servidor y plataforma.
- Los artefactos se cargan por HTTPS con hash y metadata; los bytes no se
  insertan directamente en el modelo transaccional.

Los vocabularios y formas serializadas se definen en Fase 04.

## Verificación y revocación de plugins

Fuente: [plugin verification and revocation](diagrams/13-plugin-verification-and-revocation.mmd).

1. El servidor registra un manifiesto versionado, capabilities implementadas,
   permisos, límites e integridad esperada.
2. El agente obtiene artefacto y metadata por un canal autorizado.
3. Verifica allowlist, hash, firma, trust store, versión de Plugin API y
   revocación antes de activar.
4. Sólo se permiten operaciones y argumentos registrados.
5. Una revocación impide nuevas ejecuciones y dispara tratamiento del plugin
   instalado según una política futura.

No se fija todavía algoritmo, canonicalización, formato de firma, distribución
del trust store ni SLA de revocación.
