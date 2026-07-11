# Prompt 08 - Agente Android nativo

## Objetivo

Crear una aplicación Android nativa que ejecute pruebas de red de forma honesta y compatible con restricciones modernas del sistema.

## Prerrequisitos

- Prompt 04 completo.
- Android Studio/JDK disponibles.

## Alcance

- Enrolamiento.
- Capabilities.
- Room queue.
- UI de pruebas.
- Foreground execution.
- WorkManager sync.
- Probes nativos.

## Requisitos de implementación

- Kotlin + Jetpack Compose o UI aprobada.
- Solicitar permisos mínimos y explicar su uso.
- Compatibilidad por API level; NEARBY_WIFI_DEVICES y permisos legacy según corresponda.
- No asumir scans ilimitados ni conexión silenciosa a redes.
- Foreground Service solo cuando sea válido y visible; manejar límites/timeouts por versión.
- WorkManager para sincronización diferible, no para ejecución exacta.
- OkHttp para HTTP; sockets nativos para TCP/UDP; ConnectivityManager/NetworkCallback para path.
- Room para cola offline.
- Android Keystore para secretos.
- Capturar contexto térmico/batería solo con APIs permitidas.
- Mostrar claramente WAITING_FOR_USER/FOREGROUND_REQUIRED.

## Tests obligatorios

- Unit tests.
- Instrumented tests en al menos dos API levels.
- Permiso denegado.
- App background/foreground.
- Cambio Wi-Fi/celular.
- Doze/force-stop documentado.
- Proceso terminado durante prueba.

## Documentación obligatoria

- Matriz por API level.
- Permisos y privacy.
- Guía de ejecución foreground.
- Limitaciones de scan y background.

## Criterios de aceptación

- La app no promete daemon permanente.
- Reanuda uploads sin duplicar.
- Explica tareas bloqueadas.
- Probes devuelven método y disponibilidad.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
