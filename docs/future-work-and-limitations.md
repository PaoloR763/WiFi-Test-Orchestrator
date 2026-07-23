# Capacidades pendientes y limitaciones

## Propósito y alcance

Este documento es el registro vivo, global y auditable de capacidades de WiFi
Test Orchestrator que todavía no están disponibles de forma completa. Incluye
implementación ausente o parcial, simulaciones, operación manual, validación
física pendiente, límites de entorno, recuperación de formatos históricos y
decisiones de producto abiertas.

El estado se revisó sobre la rama
`phase/07-linux-agent-and-capture-node` y el working tree existente el
2026-07-18. Una mención en un ADR, prompt, contrato o capability manifest no
demuestra por sí sola que exista una implementación operativa. Los prompts
08–26 prueban backlog documentado; no convierten automáticamente ese backlog en
defectos de la Fase 07.

Las imposibilidades deliberadas de una plataforma no son trabajo pendiente por
defecto. Por ejemplo, este inventario no promete monitor mode en iOS ni replay
en endpoints comunes. Sólo se abre una entrada cuando existe una capacidad
prevista, una implementación incompleta, una validación pendiente, una
recuperación necesaria o una decisión de producto aún modificable.

## Regla de decisión y mantenimiento

Antes de eliminar, posponer, reducir o declarar fuera de alcance una
funcionalidad relevante, se debe consultar al responsable del proyecto y
registrar la decisión. Ninguna funcionalidad se clasificará unilateralmente
como menor.

Reglas de mantenimiento:

1. No borrar una entrada cuando se complete. Moverla a
   [Elementos completados posteriormente](#8-elementos-completados-posteriormente-conservados-como-historial)
   y conservar estado anterior, evidencia y decisión de cierre.
2. Separar prioridad de producto de severidad de review, riesgo técnico o
   bloqueo operativo.
3. No promover `SIMULATED_ONLY`, un skip o una validación estática a evidencia
   física.
4. Actualizar `Última revisión` sólo después de contrastar comportamiento,
   tests, documentación y evidencia aplicable.
5. Una fase sugerida no es una fecha ni un compromiso. Sólo se registra cuando
   un documento existente la vincula con la capacidad.
6. Las entradas agregadas deben enlazar sus gates específicos para evitar
   ocultar o duplicar trabajo.

## Taxonomía de estados

| Estado | Significado |
|---|---|
| `NOT_IMPLEMENTED` | No existe una implementación productiva de la capacidad. |
| `PARTIALLY_IMPLEMENTED` | Existe una parte utilizable o infraestructura previa, pero falta comportamiento necesario para considerar completa la capacidad. |
| `IMPLEMENTED_NOT_VALIDATED` | Existe código productivo, pero falta la evidencia física, de integración o de entorno exigida para declarar soporte. |
| `MANUAL_ONLY` | La operación sólo está disponible mediante un procedimiento humano u offline documentado. |
| `SIMULATED_ONLY` | Sólo existe validación o ejecución simulada; no se realiza el efecto productivo real. |
| `DEFERRED` | La capacidad está deliberadamente postergada o vinculada a una fase futura documentada. |
| `ENVIRONMENT_LIMITED` | La implementación depende de un OS, distribución, kernel, herramienta, hardware, driver, permiso o primitiva que no está soportada o validada en todos los entornos. |
| `RECOVERY_REQUIRED` | El estado se bloquea deliberadamente y necesita recuperación manual u offline antes de continuar de forma segura. |

El estado describe la condición principal actual. Las dependencias y el
comportamiento actual registran bloqueos adicionales; por ejemplo, una
implementación puede estar a la vez sin validación física y bloqueada por una
autorización todavía inexistente.

## Prioridad de producto

| Prioridad | Significado |
|---|---|
| `CRITICAL` | Imprescindible para una operación de producto que el responsable declaró crítica. |
| `HIGH` | Desarrollo prioritario confirmado por decisión de producto. |
| `MEDIUM` | Valor relevante con prioridad de producto confirmada intermedia. |
| `LOW` | Prioridad baja confirmada expresamente; no equivale a severidad menor de review. |
| `TO_BE_DECIDED` | No existe evidencia documental suficiente para asignar prioridad; debe decidirla el responsable. |

No se reutiliza la nomenclatura ordinal de severidades de review como prioridad
de producto. Salvo la captura completa en 40 MHz, cuya prioridad `HIGH` está
decidida, las prioridades sin decisión documental permanecen
`TO_BE_DECIDED`.

## Criterio de evidencia y precedencia

La evidencia se interpreta en este orden:

1. comportamiento productivo y contratos vigentes;
2. tests que ejercitan ese comportamiento, distinguiendo fake, simulación,
   skip y hardware real;
3. documentación de la fase vigente y changelog;
4. ADRs y matriz arquitectónica como intención o baseline histórico;
5. prompts posteriores como backlog deliberado, nunca como prueba de
   implementación.

Contradicciones o ambigüedades detectadas:

- `docs/phase07/architecture.md` enumera condiciones para `capture.ip` de una
  forma que puede sugerir disponibilidad, pero
  `platforms/linux/capability_manifest.py` la fuerza a `not_implemented` y
  explica que el provider monitor/radiotap no implementa captura IP genérica.
  Este documento adopta el estado del código y de
  `docs/phase07/testing-and-limitations.md`.
- `docs/architecture/capability-matrix.md` conserva el snapshot inicial de
  Fase 01 y dice que Windows, Linux y Capture Node no estaban implementados.
  Es contexto histórico, no el estado vigente de Fases 06–07.
- `docs/development.md` pide PowerShell 7 para los scripts de desarrollo y la
  documentación de Fase 06 mantiene Windows PowerShell 5.1 como baseline y
  PowerShell 7 como matriz adicional. Son runtimes separados: la validación
  local del 2026-07-17 incorporó PowerShell 7.6.3 Core sin reemplazar 5.1. El
  job Windows de CI continúa diagnosticando explícitamente 5.1; la evidencia
  local de 7.6.3 no demuestra CI remoto ni valida integralmente la plataforma
  Windows.

## 1. Funcionalidades no implementadas

### FW-CAP-001 — Captura completa IEEE 802.11 en 40 MHz

- **Identificador estable:** `FW-CAP-001`
- **Nombre:** Captura completa IEEE 802.11 en 40 MHz.
- **Área o componente:** Agente Linux / Capture Node / monitor mode.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `HIGH`.
- **Descripción:** Agregar configuración y captura completa de canales de
  40 MHz, incluyendo `HT40+` y `HT40-`, sin confundir el ancho de la red bajo
  prueba con el ancho realmente capturado por la radio monitor.
- **Comportamiento actual:** El agente puede inventariar o trabajar en equipos
  y redes configurados en 40 MHz. La limitación afecta la configuración activa
  del Capture Node en monitor mode y la captura completa de ese ancho. Los
  únicos anchos anunciados y aceptados son 20, 80 y 160 MHz; 40 MHz se rechaza
  antes de construir el comando `iw`. Capturar 20 MHz del canal primario no
  equivale a capturar los 40 MHz completos.
- **Impacto:** Una evidencia PCAP tomada sólo sobre 20 MHz puede omitir tráfico
  del canal secundario y no permite afirmar observación completa de una
  operación HT40.
- **Motivo por el que no está completa:** La geometría privada ya representa
  control y frecuencia central para 20/80/160 MHz, pero el modelo de request,
  policy y argv `iw` todavía no representan dirección HT40 ni canal secundario.
  La decisión actual la deja fuera del cierre inmediato de Fase 07, sin reducir
  su importancia.
- **Dependencias:** Modelo explícito de primario/secundario; `HT40+`/`HT40-`;
  frecuencia central; validación por banda; política regulatoria separada;
  preflight de NIC/driver/regdomain; comandos `iw`; journal; rollback y
  recuperación tras crash.
- **Riesgos:** Configurar una combinación ilegal o ambigua, capturar sólo parte
  del canal, romper conectividad, dejar la NIC en monitor mode o restaurar un
  estado de radio incorrecto.
- **Workaround actual:** Capturar 20 MHz del primario y declarar expresamente
  cobertura parcial, o usar 80/160 MHz sólo donde la combinación admitida y el
  hardware hayan sido validados. Ningún workaround se presenta como captura
  completa de 40 MHz.
- **Criterios de aceptación:** Width 40 representado de extremo a extremo;
  `HT40+` y `HT40-` inequívocos; primario, secundario y frecuencia central
  persistidos; validación por banda y policy regulatoria independientes;
  preflight antes de mutar; argv `iw` exacto; journal durable; rollback
  verificado; recuperación tras crash; tests simulados positivos y negativos;
  validación sobre adaptador Linux real.
- **Evidencia actual:** `domain/capture_policy.py` sólo contiene
  `{20, 80, 160}`; `frequency.py` define bloques y centros cerrados para esos
  anchos, pero no modela `HT40+`/`HT40-` ni secundario; `CaptureRequest` y
  `FrequencyArguments` usan el literal `20/80/160`;
  `test_capture_commands.py::test_incomplete_or_nonexistent_iw_widths_are_rejected_before_argv`
  incluye 40; el runbook anuncia `[20, 80, 160]`.
- **Evidencia de validación requerida:** PCAP/radiotap y estado `iw` de una NIC
  real para HT40+ y HT40- por cada banda autorizada, observando ambos
  subcanales; logs de preflight; journal antes de mutar; rollback normal,
  cancelación, crash, reinicio y recuperación posterior.
- **Decisión pendiente:** Definir modelo de canal central/secundario, bandas y
  dominios regulatorios soportados, además del gate físico para declarar
  soporte.
- **Fase futura sugerida:** Sin fase numerada asignada. Está decidido que no
  entra en el cierre inmediato de Fase 07 y permanece como desarrollo
  prioritario.
- **Última revisión:** 2026-07-18.

### FW-CAP-002 — Captura IP genérica

- **Identificador estable:** `FW-CAP-002`
- **Nombre:** Provider productivo de `capture.ip`.
- **Área o componente:** Artifact plane / CaptureProvider desktop.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Capturar paquetes IP de forma genérica y acotada, con
  interfaz, filtro, duración, tamaño, formato y autorización explícitos.
- **Comportamiento actual:** Windows sólo detecta Npcap/dumpcap con fin
  diagnóstico. Linux implementa captura IEEE 802.11 en monitor mode, pero
  declara `capture.ip` como `not_implemented` y no reutiliza el provider
  radiotap como si fuera captura IP.
- **Impacto:** No existe una tarea portable de captura IP ni una afirmación
  válida de soporte basada únicamente en tener dumpcap instalado.
- **Motivo por el que no está completa:** Faltan el task type público, provider
  genérico, filtros validados, mapping de interfaces, upload y autorización de
  control plane.
- **Dependencias:** `FW-SEC-001`, `FW-ORCH-001` y `FW-ART-001`; contratos de
  task y artifacts; límites y permisos por plataforma.
- **Riesgos:** Confundir tramas radiotap con captura IP, capturar una interfaz
  sensible, exceder cuotas o exponer datos sin control de acceso.
- **Workaround actual:** Captura monitor Linux sólo para su caso especializado
  y herramientas administradas fuera del producto, con evidencia externa.
- **Criterios de aceptación:** Manifest honesto por plataforma; provider
  bounded; filtro e interfaz allowlisted; cancelación/cleanup; hash y upload;
  autorización y auditoría; tests contractuales, de integración y físicos.
- **Evidencia actual:** `linux/capability_manifest.py` fija
  `monitor_radiotap_provider_does_not_implement_capture.ip`;
  `docs/phase06/npcap-and-dumpcap.md` y `docs/phase06/limitations.md` limitan
  Windows a diagnóstico; `task-envelope.schema.json` sólo admite
  `protocol.contract_check`.
- **Evidencia de validación requerida:** Capturas reales controladas en
  Windows/Linux, filtros conocidos, timeout/tamaño, hash, upload, descarga
  autorizada y ausencia de procesos/archivos huérfanos.
- **Decisión pendiente:** Prioridad, plataformas iniciales, formatos y alcance
  exacto de filtros.
- **Fase futura sugerida:** Fase 19, según
  `prompts/19_artifacts_packet_capture_and_reports.md`.
- **Última revisión:** 2026-07-17.

### FW-SEC-001 — Autorización privilegiada emitida por el control plane

- **Identificador estable:** `FW-SEC-001`
- **Nombre:** Grant privilegiado real para captura y replay.
- **Área o componente:** Control plane / Agent Protocol / seguridad.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Emitir, transportar y validar una autorización del servidor,
  ligada al agente y capability exactos, para operaciones privilegiadas.
- **Comportamiento actual:** Producción construye
  `UnavailableControlPlaneAuthorization`. Captura monitor y replay permanecen
  fail-closed con `control_plane_authorization_unavailable`. Rol, flags,
  allowlists, dumpcap, file capabilities o configuración local sólo pueden
  restringir un grant válido; nunca otorgarlo.
- **Impacto:** Ninguna configuración local puede habilitar por sí sola captura
  privilegiada o replay, incluso si código, tool y hardware están presentes.
- **Motivo por el que no está completa:** Agent Protocol 1.0.0 carece de
  contrato, persistencia y lifecycle de grants privilegiados.
- **Dependencias:** Identidad de agente, RBAC/policy, task leasing, expiración,
  fencing, auditoría, revocación y evolución contractual compatible.
- **Riesgos:** Un grant demasiado amplio permitiría captura/replay no
  autorizado; un grant ambiguo podría reutilizarse en otro agente o capability.
- **Workaround actual:** Ninguno para producción. Tests inyectan grants
  estáticos sólo como doubles; el default productivo sigue denegando.
- **Criterios de aceptación:** Grant firmado o autenticado, acotado a agente,
  capability, task/ejecución, límites y expiración; revocable; auditable;
  resistente a replay; validado por servidor y agente; configuración local sólo
  restrictiva.
- **Evidencia actual:** `linux/capture.py` documenta el default hasta que exista
  contrato server-issued; `linux/adapter.py` siempre inyecta el provider
  unavailable; tests de captura, replay y manifest prueban que rol/tool local no
  reemplaza el grant.
- **Evidencia de validación requerida:** Contract tests old/new, grant válido,
  expirado, revocado, capability/agente incorrectos, replay, desconexión y
  auditoría end-to-end.
- **Decisión pendiente:** Autoridad emisora, formato, TTL, granularidad,
  revocación y relación con task lease/aprobación humana.
- **Fase futura sugerida:** Fases 10 y 20 documentan leases, aprobación y replay
  privilegiado; el formato exacto no está decidido.
- **Última revisión:** 2026-07-17.

### FW-LNX-001 — Scan Wi-Fi activo en Linux

- **Identificador estable:** `FW-LNX-001`
- **Nombre:** `wifi.scan` productivo en el agente Linux.
- **Área o componente:** Agente Linux / Wi-Fi endpoint.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Descubrir redes mediante un scan controlado sin presentar
  inventario pasivo como scan activo.
- **Comportamiento actual:** El manifest Linux publica `wifi.scan` como
  `not_implemented` para evitar interferir con mediciones.
- **Impacto:** El agente Linux no puede ejecutar una tarea de scan ni comparar
  resultados de scan con Windows.
- **Motivo por el que no está completa:** Faltan policy, coordinación con
  asociación/captura, permisos, throttling y task type.
- **Dependencias:** Orquestación, locks de radio, adapter NetworkManager/nl80211
  y reglas de comparabilidad.
- **Riesgos:** Interrumpir tráfico, alterar mediciones o escanear una radio
  dedicada a captura.
- **Workaround actual:** Inventario de conexión actual y datos `iw` read-only;
  no equivalen a scan.
- **Criterios de aceptación:** Preflight de interfaz/rol, límites, exclusión
  mutua con captura, resultados con source/availability, cancelación y tests en
  NIC real.
- **Evidencia actual:** `docs/phase07/testing-and-limitations.md` declara el
  scan activo no implementado; `linux/inventory.py` y el manifest usan
  `not_implemented`.
- **Evidencia de validación requerida:** NetworkManager presente/ausente,
  asociado/desasociado, conflicto con captura, permisos y radios/drivers reales.
- **Decisión pendiente:** Si se incorporará al endpoint Linux, al Capture Node
  o a ambos y con qué política de interferencia.
- **Fase futura sugerida:** Sin fase futura asignada por evidencia vigente.
- **Última revisión:** 2026-07-17.

### FW-MOB-001 — Agente Android nativo

- **Identificador estable:** `FW-MOB-001`
- **Nombre:** Aplicación agente Android.
- **Área o componente:** Mobile / Android.
- **Estado:** `IN_PROGRESS`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Agente Kotlin/Jetpack con enrolamiento, Room, WorkManager,
  Foreground Service, UI, capabilities y probes permitidos.
- **Comportamiento actual:** Existe el proyecto nativo modular
  `agents/android/`. C01 aporta bootstrap reproducible; C02A contratos wire;
  C02B dominio puro; C03 transporte HTTPS y mapping de enrolamiento en memoria;
  C04 Room v1 exclusivamente no sensible; C05 port/envelope/AAD y protección
  AES-256-GCM mediante Android Keystore en memoria. No existe todavía
  persistencia del envelope, enrolamiento durable, coordinación completa,
  WorkManager, Foreground Service, UI, capabilities, probes ni tareas remotas.
- **Impacto:** La base C01–C05 puede compilarse y probarse en host, pero todavía
  no constituye un agente Android funcional completo ni puede ejecutar pruebas.
  C05 distingue la limitación conocida de observabilidad unlocked-device en API
  29–36.0 y sólo acepta el alias v1 cuando todos los demás atributos son exactos;
  desde API 36.1 exige evidencia observada `NOT_REQUIRED`. C06 no debe consumir
  un token single-use hasta que esta corrección pase revisión independiente.
- **Motivo por el que no está completa:** Faltan C06–C14, incluida persistencia
  criptográfica coordinada, runtime/lifecycle, UI, capabilities, probes,
  instrumentación real, CI y cierre documental.
- **Dependencias:** Contratos, orquestación móvil, persistencia Room v2,
  lifecycle Android y providers de probes/tráfico.
- **Riesgos:** Prometer enrolamiento durable, no exportabilidad/hardware-backed,
  scan/background ilimitado o capacidades fuera de APIs verificadas; asumir
  evidencia positiva de unlocked-device antes de API 36.1, donde sólo existe
  una regla de compatibilidad acotada por alias y atributos observables.
- **Workaround actual:** Ninguno que equivalga a un agente. Las capas C01–C05
  permiten continuar desarrollo y tests host sin persistir plaintext.
- **Criterios de aceptación:** Completar C06–C14 y la matriz instrumentada al
  menos en API 29 y API 36/36.1, con permisos denegados, lifecycle,
  foreground/background, cambio Wi-Fi/celular, Doze, process death, Keystore,
  backup/restore y hardware presente/ausente.
- **Evidencia actual:** `agents/android/README.md` y
  `docs/phase08/c03-enrollment-transport.md`,
  `docs/phase08/c04-room-persistence.md` y
  `docs/phase08/c05-android-keystore.md`. C05 conserva Room v1 y no compone el
  adapter desde `:app`.
- **Evidencia de validación requerida:** Unit/instrumented tests, permisos
  denegados, foreground/background, cambio Wi-Fi/celular, Doze y terminación de
  proceso en dispositivos reales; provider `AndroidKeyStore`, `encoded == null`,
  TEE/StrongBox/software, invalidación, restart, uninstall y restore sin clave
  permanecen `NOT RUN` hasta C12.
- **Decisión pendiente:** Validación instrumentada/OEM de la regla unlocked-device
  en API 29 y 36.1, matriz final de API levels, canal de distribución y prioridad
  de producto.
- **Fase futura sugerida:** Fase 08 en curso; C06–C14 pendientes.
- **Última revisión:** 2026-07-22.

### FW-MOB-002 — Agente iOS/iPadOS nativo

- **Identificador estable:** `FW-MOB-002`
- **Nombre:** Aplicación agente iOS/iPadOS.
- **Área o componente:** Mobile / Apple.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** App Swift/SwiftUI foreground-first con Keychain,
  Network.framework, URLSession, cola local y capabilities honestas.
- **Comportamiento actual:** Sólo existen contratos/fixtures Swift; no hay
  proyecto de aplicación iOS.
- **Impacto:** No se pueden ejecutar campañas ni validar entitlements,
  foreground/background, cambios de path o dispositivos Apple.
- **Motivo por el que no está completa:** Implementación postergada después de
  desktop.
- **Dependencias:** Contratos, Mac/Xcode, dispositivo real y orquestación móvil.
- **Riesgos:** Prometer scan, RSSI, monitor mode, captura genérica o daemon
  permanente no expuestos por iOS.
- **Workaround actual:** Consumidor Swift de contract tests; no es un agente.
- **Criterios de aceptación:** Alcance, tests y límites del Prompt 09, con
  tareas incompatibles `BLOCKED`/`SKIPPED` y sincronización al reabrir.
- **Evidencia actual:** `mobile/README.md`, `README.md` y ausencia de un proyecto
  iOS; sólo existe `shared/contracts/consumers/swift/`.
- **Evidencia de validación requerida:** XCTest, device real, sin entitlement,
  foreground/background, app terminada y cambio de path.
- **Decisión pendiente:** Versiones mínimas efectivas, entitlements y estrategia
  TestFlight/MDM.
- **Fase futura sugerida:** Fase 09.
- **Última revisión:** 2026-07-17.

### FW-NET-001 — Probe ICMP

- **Identificador estable:** `FW-NET-001`
- **Nombre:** `network.icmp.ping`.
- **Área o componente:** Test engine / probes.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Probe ICMP portable donde el OS y permisos lo permitan.
- **Comportamiento actual:** El catálogo contiene la capability, pero desktop
  la declara no implementada y no existe plugin productivo.
- **Impacto:** No hay medición ICMP ejecutable ni fallback etiquetado desde el
  producto.
- **Motivo por el que no está completa:** Faltan task delivery, LatencyProbe,
  política de destino y adapters por plataforma.
- **Dependencias:** `FW-ORCH-001` y contrato `LatencyProbe`.
- **Riesgos:** Interpretar bloqueo ICMP como pérdida de conectividad o comparar
  ICMP con TCP/HTTP como si fueran equivalentes.
- **Workaround actual:** Diagnóstico externo manual, fuera de resultados WTO.
- **Criterios de aceptación:** Provider/método registrados, IPv4/IPv6,
  timeouts, disponibilidad, destino allowlisted y fallback explícito.
- **Evidencia actual:** `docs/phase05/limitations.md` y
  `docs/phase06/limitations.md` declaran probes ausentes; no hay provider en el
  registry desktop.
- **Evidencia de validación requerida:** Éxito, timeout, firewall, permisos,
  IPv4/IPv6 y comparación con otros métodos en Windows/Linux reales.
- **Decisión pendiente:** Plataformas y mecanismo ICMP inicial.
- **Fase futura sugerida:** Fase 11.
- **Última revisión:** 2026-07-17.

### FW-NET-002 — Probe TCP

- **Identificador estable:** `FW-NET-002`
- **Nombre:** `network.tcp.probe`.
- **Área o componente:** Test engine / probes.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Medir conexión TCP con destino, puerto, timeout y método
  registrados.
- **Comportamiento actual:** Existe el ID contractual, no un provider
  productivo.
- **Impacto:** No hay alternativa TCP controlada cuando ICMP no está disponible.
- **Motivo por el que no está completa:** Faltan LatencyProbe, task type,
  allowlist y normalización.
- **Dependencias:** `FW-ORCH-001` y políticas de destino.
- **Riesgos:** Presentar connect time como RTT ICMP o ignorar DNS/routing.
- **Workaround actual:** Herramientas externas no integradas.
- **Criterios de aceptación:** Sockets nativos, IPv4/IPv6, timeout/cancelación,
  método/source, destino autorizado y resultados no comparables bien marcados.
- **Evidencia actual:** Limitaciones de Fases 05–06 y ausencia de un plugin TCP
  en `agents/desktop/src/wto_desktop_agent/plugins/`.
- **Evidencia de validación requerida:** Puertos abiertos/cerrados, timeout,
  cancelación, cambio de path e integración desktop/mobile.
- **Decisión pendiente:** Plataformas y semántica exacta de timings.
- **Fase futura sugerida:** Fase 11.
- **Última revisión:** 2026-07-17.

### FW-NET-003 — Probe HTTP/DNS y pipeline de conectividad

- **Identificador estable:** `FW-NET-003`
- **Nombre:** `network.http.probe` y etapas DNS/HTTP de conectividad.
- **Área o componente:** Test engine / probes.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Resolver DNS y medir connect, TLS, TTFB, total, status y
  bytes con resultados por etapa.
- **Comportamiento actual:** El ID contractual existe; no hay probe HTTP
  productivo ni pipeline de conectividad.
- **Impacto:** El producto no puede localizar una falla en DNS, TLS o
  application endpoint.
- **Motivo por el que no está completa:** Faltan task orchestration, provider,
  endpoints controlados y schemas de resultado específicos.
- **Dependencias:** `FW-ORCH-001`, TLS y allowlists.
- **Riesgos:** Cache, proxy, redirects o captive portal pueden falsear
  interpretación.
- **Workaround actual:** Health checks del servidor y herramientas externas; no
  equivalen a un test del agente.
- **Criterios de aceptación:** Etapas separadas, IPv4/IPv6, DNS timeout, TLS,
  redirects, captive portal, source/method y límites.
- **Evidencia actual:** `docs/phase06/limitations.md` y ausencia de providers;
  alcance explícito en Prompt 11.
- **Evidencia de validación requerida:** Servidor controlado, DNS/TLS
  success/failure, cache/proxy y cambios de path en plataformas reales.
- **Decisión pendiente:** Endpoints iniciales y política de DNS dirigido.
- **Fase futura sugerida:** Fase 11.
- **Última revisión:** 2026-07-17.

### FW-TRF-001 — Motor de tráfico y reservas

- **Identificador estable:** `FW-TRF-001`
- **Nombre:** `TrafficGenerator`, perfiles, policy y pool de servidores.
- **Área o componente:** Data plane / traffic engine.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** API de generación de tráfico independiente de provider, con
  perfiles versionados, reservas y límites efectivos.
- **Comportamiento actual:** Existen ADRs y diseño conceptual; no existe la
  interfaz `TrafficGenerator` productiva, profile contractual ni reserva
  ejecutable.
- **Impacto:** No se puede generar tráfico real controlado ni comparar
  resultados de providers.
- **Motivo por el que no está completa:** Programado después de probes y task
  orchestration.
- **Dependencias:** `FW-ORCH-001` y `FW-NET-001`–`003`.
- **Riesgos:** Tráfico sin límite/destino, fallback silencioso o resultados no
  comparables.
- **Workaround actual:** Ninguno dentro del producto.
- **Criterios de aceptación:** API lifecycle completa, profiles inmutables,
  dry-run, reservas, policy, cancelación/cleanup y resultados normalizados.
- **Evidencia actual:** `AGENTS.md` exige la interfaz; `ports/plugins.py` sólo
  define `TestPlugin`; Prompt 12 especifica la implementación futura.
- **Evidencia de validación requerida:** Contract/golden tests, reserva
  concurrente, provider incompatible, límites y cancelación.
- **Decisión pendiente:** Primer conjunto de perfiles y autoridad de reservas.
- **Fase futura sugerida:** Fase 12.
- **Última revisión:** 2026-07-17.

### FW-TRF-002 — Provider iperf3 TCP/UDP

- **Identificador estable:** `FW-TRF-002`
- **Nombre:** Providers `traffic.tcp.throughput` y
  `traffic.udp.throughput` mediante iperf3.
- **Área o componente:** Data plane / desktop / Traffic Node.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Cliente/servidor iperf3 allowlisted con TCP/UDP, reservas,
  límites, intervals y cleanup.
- **Comportamiento actual:** iperf3 permanece fuera de Fases 06–07 y ni siquiera
  se detecta en Windows.
- **Impacto:** No hay throughput TCP/UDP productivo.
- **Motivo por el que no está completa:** Depende del motor de tráfico y pool
  controlado.
- **Dependencias:** `FW-TRF-001` y firma/hash/licencia de binarios.
- **Riesgos:** Servidores públicos, procesos/puertos huérfanos, bitrate no
  limitado o parsing incompatible.
- **Workaround actual:** iperf3 externo manual no integrado ni trazable.
- **Criterios de aceptación:** TCP/UDP, reverse/bidir según versión, JSON
  robusto, process-tree cleanup, reservas, health, hashes y raw artifact.
- **Evidencia actual:** `docs/phase06/limitations.md` y `CHANGELOG.md` dicen que
  iperf3 permanece fuera; no hay provider/command ID iperf3.
- **Evidencia de validación requerida:** Integración Windows/Linux contra nodo
  controlado, busy/collision/hang/cancelación y límites efectivos.
- **Decisión pendiente:** Versiones soportadas, distribución del binario y
  topología inicial del pool.
- **Fase futura sugerida:** Fase 13.
- **Última revisión:** 2026-07-17.

### FW-TRF-003 — Tráfico HTTP y sockets nativos

- **Identificador estable:** `FW-TRF-003`
- **Nombre:** `traffic.http.download`, `traffic.http.upload` y fallback nativo.
- **Área o componente:** Data plane / multiplataforma.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Providers HTTP y TCP/UDP nativos, especialmente para mobile,
  con endpoints controlados y resultados por método.
- **Comportamiento actual:** Los IDs existen en contratos; no hay providers ni
  endpoints de tráfico.
- **Impacto:** No hay tráfico portable ni alternativa a iperf3.
- **Motivo por el que no está completa:** Depende del motor de tráfico y de los
  agentes móviles.
- **Dependencias:** `FW-TRF-001`, `FW-MOB-001` y `FW-MOB-002`.
- **Riesgos:** Cache, payload incompleto, app suspendida, cuotas omitidas o
  falsa equivalencia con iperf3.
- **Workaround actual:** Ninguno integrado.
- **Criterios de aceptación:** Upload/download, checksum, cache prevention,
  TLS, límites, framing/acks nativos, path/thermal metadata y método explícito.
- **Evidencia actual:** No existen providers; Prompt 14 documenta el alcance
  posterior.
- **Evidencia de validación requerida:** Endpoints reales controlados,
  Windows/Linux/Android/iOS, IPv6, cambio de red y app background.
- **Decisión pendiente:** Provider inicial por plataforma y perfiles.
- **Fase futura sugerida:** Fase 14.
- **Última revisión:** 2026-07-17.

### FW-PKG-001 — Paquete RPM

- **Identificador estable:** `FW-PKG-001`
- **Nombre:** Packaging RPM para Fedora/RHEL.
- **Área o componente:** Distribución del agente Linux.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Construir, instalar, actualizar, revertir y desinstalar un
  paquete RPM equivalente al DEB dentro de la matriz aprobada.
- **Comportamiento actual:** Sólo existe DEB; Fedora/RHEL figura como diseño
  previsto.
- **Impacto:** No hay instalación soportada mediante RPM.
- **Motivo por el que no está completa:** Fase 07 priorizó DEB.
- **Dependencias:** Matriz de distro/Python, systemd, wheelhouse y pipeline de
  firma.
- **Riesgos:** Diferencias de paths, SELinux, dependencies, lifecycle y
  rollback.
- **Workaround actual:** Ningún paquete soportado; instalación ad hoc no
  equivale a soporte.
- **Criterios de aceptación:** Build reproducible, instalación offline,
  permisos, systemd, upgrade/rollback/uninstall, SELinux y tests en distro real.
- **Evidencia actual:** `docs/phase07/installation-and-distributions.md` y
  `testing-and-limitations.md` dicen “RPM no está implementado”.
- **Evidencia de validación requerida:** Fedora/RHEL seleccionados, PID 1 real,
  upgrade N-1, rollback y firma/verificación.
- **Decisión pendiente:** Distros/versiones y formato RPM objetivo.
- **Fase futura sugerida:** Fase 24 contempla diseño RPM.
- **Última revisión:** 2026-07-17.

### FW-SEC-002 — Rotación de master key de encrypted_file

- **Identificador estable:** `FW-SEC-002`
- **Nombre:** Rotación transaccional de master key.
- **Área o componente:** Agente Linux / SecretStore.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Rotar la master key y reenvolver secretos sin pérdida,
  exposición ni estado mixto.
- **Comportamiento actual:** Reemplazar manualmente la key falla cerrado; Fase
  07 no rota.
- **Impacto:** No existe lifecycle soportado de rotación periódica o por
  incidente.
- **Motivo por el que no está completa:** Falta protocolo transaccional,
  recovery y compatibilidad de formatos.
- **Dependencias:** Completion guard, backup, journal de rotación y herramienta
  offline/online decidida.
- **Riesgos:** Perder secretos, aceptar ciphertext con key incorrecta o dejar
  dos generaciones ambiguas.
- **Workaround actual:** Mantener y proteger la key existente; recovery del
  agente si se pierde, sin sustitución manual.
- **Criterios de aceptación:** Plan durable, idempotencia, crash recovery,
  rollback, zeroization razonable y pruebas de todas las ventanas de falla.
- **Evidencia actual:** `docs/phase07/security-and-permissions.md` y
  `testing-and-limitations.md` declaran la rotación ausente.
- **Evidencia de validación requerida:** Fallas inyectadas antes/después de cada
  commit, reinicio, rollback y recuperación de secretos reales de prueba.
- **Decisión pendiente:** Rotación online u offline, formato y custodia.
- **Fase futura sugerida:** Sin fase futura asignada.
- **Última revisión:** 2026-07-17.

### FW-INT-001 — Adaptadores de infraestructura externa

- **Identificador estable:** `FW-INT-001`
- **Nombre:** `InfrastructureAdapter` para AP, gateway, ONT y controlador.
- **Área o componente:** Integration plane.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Leer y correlacionar telemetría externa y aplicar cambios
  controlados con snapshot/rollback.
- **Comportamiento actual:** `integrations/` sólo contiene un README de reserva;
  no hay adapters ni operaciones externas.
- **Impacto:** No se correlacionan resultados con infraestructura ni se
  gestionan cambios desde WTO.
- **Motivo por el que no está completa:** Backlog posterior a dominio y
  contratos estables.
- **Dependencias:** Secret store, RBAC, auditoría, telemetry plane y SDK.
- **Riesgos:** SSH genérico, credenciales expuestas, datos stale o writes sin
  rollback.
- **Workaround actual:** Operación externa/manual sin integración ni
  correlación automática.
- **Criterios de aceptación:** Interfaces versionadas, source/freshness,
  timeout/retry/circuit breaker, mapping con confianza y writes privilegiados
  con snapshot/validate/rollback.
- **Evidencia actual:** `integrations/README.md` declara que no existen
  operaciones; Prompt 21 define el backlog.
- **Evidencia de validación requerida:** Adapter simulado contractual y al
  menos un sistema autorizado real, incluyendo failure/rollback.
- **Decisión pendiente:** Primer protocolo/proveedor y si la primera entrega es
  read-only.
- **Fase futura sugerida:** Fase 21.
- **Última revisión:** 2026-07-17.

### FW-OPS-001 — Cleanup de replays secretos e idempotencia

- **Identificador estable:** `FW-OPS-001`
- **Nombre:** Limpieza por lotes de `SecretReplay` e idempotency records.
- **Área o componente:** Backend / mantenimiento.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Eliminar registros expirados en orden seguro, por lotes y
  con observabilidad.
- **Comportamiento actual:** Se persisten expiraciones, pero no hay scheduler de
  cleanup.
- **Impacto:** Los registros expirados pueden crecer hasta mantenimiento
  externo de base de datos.
- **Motivo por el que no está completa:** Fase 04 postergó el scheduler.
- **Dependencias:** Worker/scheduler, locks, métricas y política de retención.
- **Riesgos:** Borrar un replay aún necesario o generar locks/carga excesiva.
- **Workaround actual:** Monitoreo y mantenimiento de base de datos fuera del
  runtime; no hay comando WTO soportado.
- **Criterios de aceptación:** Orden replay→record, lotes, idempotencia,
  concurrencia, métricas, auditoría aplicable y pruebas con expiración.
- **Evidencia actual:** `docs/phase04/enrollment-and-credentials.md` dice
  “Cleanup futuro” y que no se agrega scheduler.
- **Evidencia de validación requerida:** PostgreSQL real con lotes,
  concurrencia, crash/retry y límites de duración.
- **Decisión pendiente:** Retención, frecuencia y ownership operativo.
- **Fase futura sugerida:** Sin fase futura asignada.
- **Última revisión:** 2026-07-17.

### FW-OPS-002 — Purga y legal hold de auditoría

- **Identificador estable:** `FW-OPS-002`
- **Nombre:** Retención operativa de AuditLog.
- **Área o componente:** Backend / auditoría.
- **Estado:** `NOT_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Procedimiento privilegiado y auditable de retención/purga
  compatible con legal hold.
- **Comportamiento actual:** AuditLog es append-only para aplicación/rol
  runtime; no hay purga automática.
- **Impacto:** La tabla crece y la retención objetivo no se aplica
  automáticamente.
- **Motivo por el que no está completa:** Diferida a una fase operativa.
- **Dependencias:** Policy legal, permisos separados, particionado/backup y
  observabilidad.
- **Riesgos:** Destruir evidencia, violar legal hold o habilitar delete al rol
  runtime.
- **Workaround actual:** Administración manual de PostgreSQL fuera del rol
  runtime, bajo procedimiento externo.
- **Criterios de aceptación:** Selección verificable, aprobación, legal hold,
  audit trail, backup/restore y ausencia de privilegio de delete en runtime.
- **Evidencia actual:** `docs/phase03/audit.md` y `README.md` de Fase 03
  declaran la purga ausente.
- **Evidencia de validación requerida:** Base real con retención, hold,
  rollback/restore y verificación de permisos.
- **Decisión pendiente:** Plazo, legal hold, particionado y autoridad.
- **Fase futura sugerida:** Sin fase futura concreta asignada.
- **Última revisión:** 2026-07-17.

### FW-OPS-003 — Alta disponibilidad y disaster recovery

- **Identificador estable:** `FW-OPS-003`
- **Nombre:** HA, backup/restore y disaster recovery productivos.
- **Área o componente:** Servidor / operación.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Eliminar o gestionar puntos únicos de falla y demostrar
  recuperación coherente de PostgreSQL, Redis y artifacts.
- **Comportamiento actual:** El MVP acepta un único control plane sin failover;
  RPO 24 h/RTO 4 h son objetivos provisionales, no SLA ni resultados probados.
- **Impacto:** Una falla de host o storage puede requerir recuperación manual y
  exceder objetivos no validados.
- **Motivo por el que no está completa:** HA quedó expresamente fuera del MVP y
  backup/restore sigue como decisión diferida.
- **Dependencias:** Topología, storage, reconciliación, observabilidad, runbooks
  y pruebas de restore.
- **Riesgos:** Historia divergente entre DB/Redis/artifacts o falsa confianza en
  RPO/RTO.
- **Workaround actual:** Backups y operación del entorno a cargo de la
  infraestructura; sin garantía WTO end-to-end.
- **Criterios de aceptación:** Política aprobada, backups verificables, restore
  probado, reconciliación, failover si se incorpora HA y RPO/RTO medidos.
- **Evidencia actual:** ADR-0001 y ADR-0015 declaran HA fuera del MVP y
  backup/restore como decisión diferida.
- **Evidencia de validación requerida:** Ejercicios de pérdida de PostgreSQL,
  Redis y artifact store, restore coherente y medición de RPO/RTO.
- **Decisión pendiente:** Si/cuándo incorporar HA, topología, objetivos y
  presupuesto operativo.
- **Fase futura sugerida:** Fases 23 y 26 incluyen backup/restore y gates E2E.
- **Última revisión:** 2026-07-17.

## 2. Funcionalidades parcialmente implementadas

### FW-ORCH-001 — Orquestación y entrega real de tareas

- **Identificador estable:** `FW-ORCH-001`
- **Nombre:** Queueing, leases, claims, progress, cancelación y resultados.
- **Área o componente:** Control plane / agente desktop/mobile.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ciclo de vida de tareas con delivery outbound-only,
  idempotencia, expiración, fencing, recuperación y estados explicables.
- **Comportamiento actual:** El desktop tiene scheduler, TaskRunner, SQLite y
  outboxes locales ejercitados con `SimulatedAgentTransport`. El servidor sólo
  expone stubs internos; `task-fetch` responde `no_task` y el schema público
  sólo acepta `protocol.contract_check`.
- **Impacto:** Captura, probes, tráfico y campañas no pueden entregarse como
  tareas productivas ni cerrar resultados/artifacts contra el servidor.
- **Motivo por el que no está completa:** Fase 05 preservó modelos locales hasta
  que exista contrato autoritativo de Fase 10.
- **Dependencias:** Evolución de Agent Protocol, cola/worker, leases, capability
  preflight y mobile hints.
- **Riesgos:** Doble efecto, lease vencido, progress fuera de orden o borrar
  outbox sin ack durable.
- **Workaround actual:** Simulación local y stubs autenticados; no se presentan
  como API estable.
- **Criterios de aceptación:** Estados completos, lease/fencing, claims
  atómicos, cancelación/cleanup, no doble ejecución efectiva, recuperación
  desktop y semántica mobile no inmediata.
- **Evidencia actual:** `docs/phase05/README.md`,
  `docs/phase04/protocol.md`, `backend/api/routers/agent_protocol.py` y
  `task-envelope.schema.json`.
- **Evidencia de validación requerida:** PostgreSQL/Redis reales, carreras de
  claim, expiración, offline/reconnect, duplicados, cancelación durante upload y
  chaos tests.
- **Decisión pendiente:** Máquina de estados final, TTL/renewal, canal live para
  UI y ventana de compatibilidad.
- **Fase futura sugerida:** Fase 10.
- **Última revisión:** 2026-07-17.

### FW-CAP-003 — Rol autoritativo Capture Node/Lab Node

- **Identificador estable:** `FW-CAP-003`
- **Nombre:** Rol especializado emitido y gobernado por servidor.
- **Área o componente:** Enrollment / control plane / Capture Node.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Representar Capture Node/Lab Node en identidad, enrollment,
  policy y autorización del servidor.
- **Comportamiento actual:** `node_role` es policy local y el manifest lo
  refleja indirectamente. Enrollment 1.0.0 no tiene rol especializado; la
  configuración local no concede privilegios.
- **Impacto:** El servidor no puede gobernar de forma autoritativa qué agentes
  son Capture/Lab Nodes.
- **Motivo por el que no está completa:** Fase 07 evitó cambiar contratos
  públicos y dejó la evolución contractual futura.
- **Dependencias:** `FW-SEC-001`, enrollment, RBAC/policy y compatibilidad de
  Agent Protocol.
- **Riesgos:** Confundir label local con autorización o habilitar un endpoint
  común.
- **Workaround actual:** Rol local deny-by-default más grant unavailable; sólo
  restringe.
- **Criterios de aceptación:** Rol server-side versionado, enrollment/recovery,
  revocación, manifest coherente, policy por capability y migración compatible.
- **Evidencia actual:** `docs/phase07/testing-and-limitations.md` y
  `architecture.md` declaran que enrollment 1.0.0 no contiene el rol.
- **Evidencia de validación requerida:** Enrollment/rotation/recovery, cambio de
  rol autorizado, revocación, agente antiguo y endpoint que intenta replay.
- **Decisión pendiente:** Separar o combinar Capture Node y Lab Node, permisos y
  lifecycle del rol.
- **Fase futura sugerida:** Fase 20 define LabNode; la evolución previa del
  contrato no tiene fase exacta asignada.
- **Última revisión:** 2026-07-17.

### FW-REPLAY-001 — Tcpreplay real

- **Identificador estable:** `FW-REPLAY-001`
- **Nombre:** Provider productivo `traffic.pcap.replay`.
- **Área o componente:** Lab Node / data plane privilegiado.
- **Estado:** `SIMULATED_ONLY`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ejecutar replay acotado en Linux especializado, aislado y
  autorizado.
- **Comportamiento actual:** `TcpreplayValidator` valida rol, policy, tool,
  namespace, interface/scenario allowlists, hash y cotas, y luego sólo simula
  status/cleanup. Su docstring afirma que nunca invoca tcpreplay. Producción
  también queda bloqueada por `FW-SEC-001`.
- **Impacto:** No se envía ningún paquete real; una simulación válida no
  demuestra replay ni aislamiento de red real.
- **Motivo por el que no está completa:** Replay real se excluyó deliberadamente
  de Fase 07 por privilegios/namespace y contrato futuro.
- **Dependencias:** `FW-SEC-001`, `FW-CAP-003`, `FW-ORCH-001`,
  `FW-ART-001`, namespace/lab aislado y provider allowlisted.
- **Riesgos:** Tráfico hacia red pública, replay indefinido, PCAP no aprobado,
  escape de namespace o procesos remanentes.
- **Workaround actual:** Validación/simulación y cleanup; tcpreplay externo no
  forma parte del producto.
- **Criterios de aceptación:** ReplayProfile versionado, aprobación extra,
  detección de ruta pública, aislamiento, rate/loops/duration, counters,
  cancelación, cgroup cleanup y auditoría.
- **Evidencia actual:** `linux/replay.py`, tests
  `test_replay_and_process.py` y documentación de Fase 07 dicen explícitamente
  “no invoca tcpreplay real”.
- **Evidencia de validación requerida:** Lab descartable, red aislada, tráfico
  observado, wrong interface/public route, timeout/cancelación, cgroup vacío y
  auditoría.
- **Decisión pendiente:** Modelo de privilegio/namespace, aprobaciones y primer
  perfil permitido.
- **Fase futura sugerida:** Fase 20.
- **Última revisión:** 2026-07-17.

### FW-REPLAY-002 — Provisioning administrativo de artifacts de replay

- **Identificador estable:** `FW-REPLAY-002`
- **Nombre:** Artifacts root-owned con grupo Linux dedicado.
- **Área o componente:** Lab Node / artifact plane / permisos Linux.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Evaluar provisioning administrativo donde los artifacts
  aprobados pertenezcan a root, tengan grupo dedicado y modo `0440`.
- **Comportamiento actual:** La política aprobada usa directorio `0700`, archivo
  regular `0400` o `0600`, owner igual al usuario efectivo del servicio y
  `st_nlink == 1`. Replay rechaza root owner, grupo dedicado y `0440`.
- **Impacto:** Un administrador no puede aprovisionar artifacts inmutables por
  grupo sin transferirlos antes al usuario del servicio bajo la política actual.
- **Motivo por el que no está completa:** Requiere decidir lifecycle de grupo,
  provisioning, rotación, auditoría y frontera de escritura administrativa.
- **Dependencias:** `FW-REPLAY-001`, packaging Linux, unidad systemd y runbook
  administrativo.
- **Riesgos:** Ampliar lectura a un grupo incorrecto, aceptar owner/mode
  ambiguos o mezclar provisioning con el runtime privilegiado.
- **Workaround actual:** Aprovisionar sólo bajo la política service-user
  `0700` + `0400/0600`; no usar `0440`.
- **Criterios de aceptación:** Decisión explícita de producto; grupo dedicado
  versionado; installer/upgrade/rollback; owner/mode/nlink fail-closed; tests de
  provisioning y revocación.
- **Evidencia actual:** `linux/replay.py`, `test_replay_and_process.py` y el
  runbook de Capture Node fijan la política vigente.
- **Evidencia de validación requerida:** Instalación limpia, upgrade, rollback,
  revocación de grupo, artifact válido/inválido y auditoría sin lectura de bytes.
- **Decisión pendiente:** Si adoptar root owner + grupo dedicado + `0440` y en
  qué fase.
- **Fase futura sugerida:** Sin fase numerada asignada.
- **Última revisión:** 2026-07-18.

### FW-FLENT-001 — Provider operativo de Flent

- **Identificador estable:** `FW-FLENT-001`
- **Nombre:** Flent para `traffic.latency_under_load`.
- **Área o componente:** Traffic engine / agente Linux.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ejecutar Flent/netperf opcional e importar series/metadata
  como provider, sin hacerlo dependencia del producto.
- **Comportamiento actual:** Se detectan Flent y netperf; el manifest puede
  anunciar `linux-flent` sólo con flag, allowlist y cgroup. No existe ejecución
  de task ni importación de resultado; la documentación dice que espera
  contrato futuro.
- **Impacto:** Provider “available” en condiciones locales no demuestra una
  prueba Flent ejecutable end-to-end.
- **Motivo por el que no está completa:** Faltan task contract, TrafficGenerator
  y parser/importador.
- **Dependencias:** `FW-ORCH-001`, `FW-TRF-001` y cgroup real validado.
- **Riesgos:** Sobreanunciar implementación, usar netperf remoto libre o
  atribuir bufferbloat sin evidencia.
- **Workaround actual:** Detección/manifest condicional; Flent manual externo no
  se incorpora como resultado WTO.
- **Criterios de aceptación:** Task allowlisted, servidor aprobado, ejecución
  contenida, JSON/raw artifact, series alineadas y fallback compuesto sin
  Flent.
- **Evidencia actual:** `linux/capability_manifest.py` marca implementación
  `partial` sólo si hay readiness; `docs/phase07/testing-and-limitations.md`
  dice “sólo se detecta/declara”.
- **Evidencia de validación requerida:** Flent/netperf reales, servidor
  controlado, cancelación, cgroup cleanup, importación JSON y comparación con
  provider compuesto.
- **Decisión pendiente:** Versiones/perfiles Flent, servidores y prioridad
  respecto del runner compuesto.
- **Fase futura sugerida:** Fase 15.
- **Última revisión:** 2026-07-17.

### FW-ART-001 — Artifact plane remoto y reportes

- **Identificador estable:** `FW-ART-001`
- **Nombre:** Upload de bytes, S3/MinIO, descarga y reportes.
- **Área o componente:** Artifact plane.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Persistir artifacts íntegros con upload resumable, cuotas,
  autorización, retención y `ReportRenderer`.
- **Comportamiento actual:** Backend tiene readiness de filesystem local y
  esqueletos de metadata; desktop/Capture Node hace staging y outbox local con
  hash. El protocolo no acepta bytes, no hay upload público, S3/MinIO,
  descarga autorizada ni renderers.
- **Impacto:** PCAP y otros artifacts no llegan de forma productiva al servidor
  ni generan reportes trazables.
- **Motivo por el que no está completa:** Fases 03–04 crearon límites/esqueletos
  y Fase 07 sólo staging local.
- **Dependencias:** `FW-ORCH-001`, storage, cuotas, auth y retención.
- **Riesgos:** Pérdida tras crash, hash mismatch, path malicioso, acceso no
  autorizado o crecimiento sin retención.
- **Workaround actual:** Outbox local/simulada y filesystem de desarrollo.
- **Criterios de aceptación:** Upload resumable, ack durable, filesystem y
  S3/MinIO, hash/quota, signed/authenticated download, retention/legal hold y
  HTML/PDF/CSV/JSON reproducibles.
- **Evidencia actual:** `docs/phase07/capture-node-runbook.md` dice que staging
  no es upload; `phase04/operations.md` dice que el API no acepta bytes;
  `backend/artifact_store.py` sólo implementa readiness local.
- **Evidencia de validación requerida:** Upload interrumpido, hash mismatch,
  cuota, descarga no autorizada, S3/MinIO real y report determinista.
- **Decisión pendiente:** Protocolo multipart/resumable, backend inicial y
  política de retención.
- **Fase futura sugerida:** Fase 19.
- **Última revisión:** 2026-07-17.

### FW-CAMP-001 — Casos, suites, planes, campañas y comparación

- **Identificador estable:** `FW-CAMP-001`
- **Nombre:** Gestión reproducible de pruebas.
- **Área o componente:** Control plane / dominio de campañas.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Versionar TestCase/Suite/Plan/Campaign, snapshots,
  scheduling, thresholds, baselines y comparaciones.
- **Comportamiento actual:** Backend sólo contiene esqueletos mínimos
  `TestDefinition`, `Campaign` y `Execution` sin API funcional, máquina de
  estados, suites/planes ni comparison engine.
- **Impacto:** No se pueden diseñar o ejecutar campañas reproducibles ni
  conservar PASS/FAIL histórico completo.
- **Motivo por el que no está completa:** Los modelos de continuidad de Fase 03
  no afirman la funcionalidad posterior.
- **Dependencias:** Orquestación, probes/tráfico, telemetry y artifacts.
- **Riesgos:** Cambiar semántica histórica, comparar métodos incompatibles o
  ejecutar targets sin capability.
- **Workaround actual:** Ninguno como workflow de producto.
- **Criterios de aceptación:** Published versions inmutables, snapshot,
  preflight, scheduling/concurrency, rerun, baselines y comparabilidad
  explícita.
- **Evidencia actual:** `docs/phase03/README.md` llama a estos modelos
  “esqueletos de continuidad”; migración 0003 sólo crea columnas mínimas.
- **Evidencia de validación requerida:** Publish/snapshot, campaña heterogénea,
  rerun, scheduling, concurrencia e inmutabilidad histórica.
- **Decisión pendiente:** Modelo funcional inicial y prioridades de workflows.
- **Fase futura sugerida:** Fase 17.
- **Última revisión:** 2026-07-17.

### FW-UI-001 — Dashboards y workflows de operador

- **Identificador estable:** `FW-UI-001`
- **Nombre:** UI operativa completa.
- **Área o componente:** Frontend React.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Inventario, capabilities, campaign builder, progreso,
  resultados, telemetría, artifacts y administración.
- **Comportamiento actual:** La UI de Fase 02 muestra health e inventario de
  agentes simulados; no implementa los workflows de operación.
- **Impacto:** El producto no puede operarse end-to-end desde la web.
- **Motivo por el que no está completa:** Depende de APIs y dominio de fases
  posteriores.
- **Dependencias:** `FW-CAMP-001`, `FW-TEL-001` y `FW-ART-001`.
- **Riesgos:** Ocultar `SKIPPED/BLOCKED`, aplicar RBAC sólo en UI o graficar
  métodos no comparables.
- **Workaround actual:** APIs internas/Swagger y procedimientos de desarrollo;
  no son workflow de operador.
- **Criterios de aceptación:** Pantallas accesibles, RBAC backend/UI, preflight,
  live progress, gráficos con método, comparator y artifacts.
- **Evidencia actual:** `frontend/src/App.tsx` se identifica como “Phase 02
  development environment”; Prompt 18 define el alcance pendiente.
- **Evidencia de validación requerida:** Component/contract/Playwright,
  accessibility, paginación y reconexión.
- **Decisión pendiente:** Primer workflow vertical y diseño visual.
- **Fase futura sugerida:** Fase 18.
- **Última revisión:** 2026-07-17.

### FW-TEL-001 — Telemetría, eventos y calidad temporal

- **Identificador estable:** `FW-TEL-001`
- **Nombre:** Pipeline productivo de telemetry plane.
- **Área o componente:** Agentes / backend / telemetry plane.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ingerir batches idempotentes, conservar calidad temporal,
  detectar eventos y aplicar retención/downsampling.
- **Comportamiento actual:** Agentes normalizan inventario/campos y backend
  posee esqueletos `Metric`/correlation; Fase 06 no publica inventario o
  telemetría y no hay pipeline de batches/eventos.
- **Impacto:** No existen series, eventos Wi-Fi correlacionados, exports ni
  dashboards temporales productivos.
- **Motivo por el que no está completa:** Infraestructura y modelos iniciales no
  incluyen ingestión/retención.
- **Dependencias:** Contratos de samples/events, storage y orquestación.
- **Riesgos:** Duplicados, reloj incorrecto, gaps ocultos, cardinalidad o
  retención sin medir.
- **Workaround actual:** Heartbeat/presence e inventario local, sin equivaler a
  telemetry plane.
- **Criterios de aceptación:** Batches idempotentes, clock quality/skew/jumps,
  events explicables, retention/downsampling, CSV/JSON y métricas de ingest.
- **Evidencia actual:** `docs/phase06/README.md` dice que ingestión sigue
  diferida; Prompt 16 define el pipeline.
- **Evidencia de validación requerida:** Duplicado, out-of-order, clock jump,
  backlog offline, debounce, retention y load tests.
- **Decisión pendiente:** Backend físico, retención y fuentes/eventos iniciales.
- **Fase futura sugerida:** Fase 16.
- **Última revisión:** 2026-07-17.

### FW-PLUG-001 — SDK formal de plugins

- **Identificador estable:** `FW-PLUG-001`
- **Nombre:** Plugin manifests, trust, discovery y conformance.
- **Área o componente:** Extensibilidad.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Formalizar `TestPlugin`, `TrafficGenerator`,
  `CaptureProvider`, `InfrastructureAdapter` y `ReportRenderer` con versionado y
  firma/allowlist.
- **Comportamiento actual:** Desktop define `TestPlugin`/`PluginDescriptor` y un
  plugin sin efectos `protocol.contract_check`. No existen SDK completo,
  manifests firmados, discovery, migraciones ni suites de conformance.
- **Impacto:** Agregar providers reales requiere trabajo ad hoc y no hay cadena
  de confianza completa.
- **Motivo por el que no está completa:** Fase 05 implementó sólo el boundary
  mínimo.
- **Dependencias:** Interfaces restantes, esquema PluginManifest, trust store y
  feature flags.
- **Riesgos:** Carga de código arbitrario, incompatibilidad o migración sin
  rollback.
- **Workaround actual:** Registry local cerrado con plugin incorporado.
- **Criterios de aceptación:** Manifest/version negotiation, config/result
  schemas, firma/allowlist, staged rollout, deprecation y conformance suite.
- **Evidencia actual:** `ports/plugins.py` sólo contiene `TestPlugin`;
  `plugins/registry.py` es local; Prompt 22 documenta el SDK futuro.
- **Evidencia de validación requerida:** Plugin incompatible, firma inválida,
  old/new server-agent, migración/rollback y ejemplo sin modificar core.
- **Decisión pendiente:** Formato de firma, trust store y superficie inicial.
- **Fase futura sugerida:** Fase 22.
- **Última revisión:** 2026-07-17.

### FW-PKG-002 — Distribución firmada y actualizaciones

- **Identificador estable:** `FW-PKG-002`
- **Nombre:** Installers finales, code signing y update service.
- **Área o componente:** Packaging / release.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Entregables firmados, upgrades/rollback compatibles y
  rollout controlado por plataforma.
- **Comportamiento actual:** Windows tiene PyInstaller onedir y scripts
  preliminares; Linux tiene DEB reproducible. No hay MSI/MSIX/WiX, RPM,
  code-signing real, update manifest/service ni auto-update.
- **Impacto:** No existe canal de distribución productivo verificable y
  portable.
- **Motivo por el que no está completa:** Packaging actual valida bases de
  Fases 06–07; release completo está postergado.
- **Dependencias:** `FW-PKG-001`, PKI/signing, compatibility window y release
  gates.
- **Riesgos:** Supply chain, downgrade incompatible, update interrumpido o
  rollback sin backup.
- **Workaround actual:** Scripts administrados y bundles preliminares.
- **Criterios de aceptación:** Firma/hash, MSI/instalador aprobado, DEB/RPM,
  update manifest, staged rollout, kill switch, N-1 upgrade y rollback.
- **Evidencia actual:** `docs/phase06/limitations.md` y Prompt 24; Fase 07 sólo
  prueba DEB.
- **Evidencia de validación requerida:** Fresh install, upgrade, rollback,
  interrupción, firma inválida y compatibilidad old agent/new server.
- **Decisión pendiente:** Canales, autoridad de firma y primer installer final.
- **Fase futura sugerida:** Fase 24.
- **Última revisión:** 2026-07-17.

### FW-SECOPS-001 — Hardening, observabilidad y release gates completos

- **Identificador estable:** `FW-SECOPS-001`
- **Nombre:** Baseline productivo de seguridad/observabilidad/CI.
- **Área o componente:** Plataforma completa.
- **Estado:** `PARTIALLY_IMPLEMENTED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Completar TLS/mTLS o credenciales decididas, scans, SBOM,
  firmas, métricas/traces, alertas, load/chaos y restore gates.
- **Comportamiento actual:** Hay auth, RBAC, rate limits, logs estructurados,
  threat model y CI de superficies existentes. No hay baseline completo
  multiplataforma, SBOM/firma de release, OpenTelemetry, load/chaos general ni
  restore probado.
- **Impacto:** No existe un gate de release productivo integral.
- **Motivo por el que no está completa:** Depende de funcionalidad principal y
  agentes futuros.
- **Dependencias:** Mobile, tráfico, artifacts, packaging y `FW-OPS-003`.
- **Riesgos:** Vulnerabilidades no detectadas, diagnóstico insuficiente o
  release no reproducible.
- **Workaround actual:** Controles y CI parciales por fase.
- **Criterios de aceptación:** Alcance y gates de Prompt 23, con vulnerabilidades
  críticas bloqueantes, métricas diagnósticas y restore probado.
- **Evidencia actual:** `docs/phase04/operations.md` deja mTLS/PKI futuro;
  ADR-0015 deja DR diferido; Prompt 23 enumera controles restantes.
- **Evidencia de validación requerida:** SAST/SCA/container/secret scans, SBOM,
  load/chaos, outages, backup restore y clean checkout.
- **Decisión pendiente:** Trust model, tooling, SLOs y release policy.
- **Fase futura sugerida:** Fase 23.
- **Última revisión:** 2026-07-17.

## 3. Funcionalidades implementadas pero no validadas físicamente

### FW-VAL-LNX-001 — Monitor mode y rollback sobre NIC real

- **Identificador estable:** `FW-VAL-LNX-001`
- **Nombre:** Validación física de `capture.ieee80211.monitor`.
- **Área o componente:** Capture Node Linux.
- **Estado:** `IMPLEMENTED_NOT_VALIDATED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Probar entrada/salida de monitor mode, radiotap, canales,
  anchos y restauración sobre hardware real.
- **Comportamiento actual:** El coordinator, preflight, snapshot, journal,
  comandos, dumpcap, staging y rollback existen. Tests usan backends simulados,
  fixtures y fake dumpcap; el rollback modela `AP` canónico y emite el token
  `__ap` verificado para Ubuntu 24.04 `iw` 6.7, y restaura múltiples conexiones
  NetworkManager con secundaria por UUID y primaria final. CI nunca cambia una
  interfaz ni inicia monitor mode. Producción sigue fail-closed además por
  `FW-SEC-001`.
- **Impacto:** No puede declararse soporte sobre ninguna combinación concreta de
  NIC/driver/firmware/banda.
- **Motivo por el que no está completa:** No se ejecutó el runbook en un host
  Linux descartable con radio dedicada.
- **Dependencias:** Grant de laboratorio controlado, NIC real, NetworkManager,
  iw, dumpcap, cgroup y consola local.
- **Riesgos:** Pérdida de conexión, radiotap ausente/incorrecto, canal no
  aplicado, rollback incompleto o NIC inutilizable hasta intervención.
- **Workaround actual:** Simulación y validación estática; no equivalen a
  soporte físico.
- **Criterios de aceptación:** NIC real; entrada y salida monitor; radiotap;
  canales y anchos admitidos; rollback desde managed, AP y demás tipos
  explícitamente soportados; una y múltiples conexiones activas con primaria
  preservada; success/failure/cancelación; reinicio; pérdida de conexión; crash
  y recuperación posterior.
- **Evidencia actual:** `docs/phase07/README.md` y
  `testing-and-limitations.md` niegan validación de NIC real; tests unitarios
  prueban la state machine simulada, el mapper `AP` → `__ap`, los checkpoints
  por UUID y el restart sin repetir mutadores confirmados.
- **Evidencia de validación requerida:** Matriz con distro/kernel,
  NetworkManager, NIC/chipset, driver, firmware, wiphy, banda/canal/ancho,
  dumpcap, PCAP/radiotap y resultado de cada recuperación.
- **Decisión pendiente:** Matriz mínima de hardware que constituirá soporte.
- **Fase futura sugerida:** Sin fase numerada; gate físico pendiente posterior a
  Fase 07.
- **Última revisión:** 2026-07-18.

### FW-VAL-LNX-002 — dumpcap real

- **Identificador estable:** `FW-VAL-LNX-002`
- **Nombre:** Ejecución controlada de dumpcap real.
- **Área o componente:** Capture Node / provider Linux.
- **Estado:** `IMPLEMENTED_NOT_VALIDATED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Demostrar el wiring productivo con el binario real, permisos
  mínimos, descriptor preabierto, PCAP/PCAPNG y cleanup.
- **Comportamiento actual:** El command spec real ejecutaría
  `dumpcap -i ... -I -y ... -w -` y escribe stdout en un descriptor reservado. CI ejecuta un fake
  dumpcap que atraviesa coordinator/runner/spawn guard; no captura hardware.
- **Impacto:** El fake prueba lifecycle y bytes, no acceso real a la NIC,
  file capabilities, formato radiotap ni comportamiento del binario instalado.
- **Motivo por el que no está completa:** dumpcap real y sus permisos no se
  ejecutaron en el host de laboratorio requerido.
- **Dependencias:** `FW-VAL-LNX-001`, dumpcap seguro, CAP_NET_RAW/CAP_NET_ADMIN
  acotadas y `FW-SEC-001`.
- **Riesgos:** Ejecutable inseguro, acceso denegado, DLT inesperado, buffer/size
  behavior distinto o proceso remanente.
- **Workaround actual:** Fake dumpcap para automatización y
  `dumpcap -D -M` manual como preflight administrativo.
- **Criterios de aceptación:** Self-check y enumerate bajo cuenta del servicio,
  captura real limitada, radiotap, formatos, stderr separado, size/timeout,
  cancelación y cero procesos/archivos huérfanos.
- **Evidencia actual:** `tests/fixtures/linux/fake_dumpcap.py` y
  `test_capture_descriptor.py`; documentación de Fase 07 declara dumpcap real
  pendiente.
- **Evidencia de validación requerida:** Comando/version/hash/permisos, PCAP
  parseable con paquetes conocidos, límites, fallas y cleanup en hardware real.
- **Decisión pendiente:** Versiones/distribuciones de dumpcap soportadas y
  mecanismo de permisos aprobado.
- **Fase futura sugerida:** Sin fase numerada asignada.
- **Última revisión:** 2026-07-17.

### FW-VAL-LNX-003 — systemd real como PID 1

- **Identificador estable:** `FW-VAL-LNX-003`
- **Nombre:** Lifecycle real de unidades systemd.
- **Área o componente:** Servicio/packaging Linux.
- **Estado:** `IMPLEMENTED_NOT_VALIDATED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ejecutar endpoint y Capture Node bajo systemd real como PID 1,
  con cuentas, hardening, restart, upgrade y shutdown.
- **Comportamiento actual:** Hay unidades, validación estática
  `systemd-analyze verify` y runtime DEB en contenedor. Ese runtime reemplaza
  `/usr/bin/systemctl` por un simulador que inicia `sleep`; el servicio real no
  fue iniciado por systemd PID 1.
- **Impacto:** El DEB runtime prueba instalación/upgrade y una simulación de
  lifecycle, no cgroups/delegación/credenciales/hardening aplicados por systemd
  real.
- **Motivo por el que no está completa:** CI no arranca un host/VM con systemd
  real como init.
- **Dependencias:** VM/host descartable, DEB, cuentas de servicio y cgroup v2.
- **Riesgos:** Directivas incompatibles, paths/permisos incorrectos, restart
  loops o delegación distinta a la simulada.
- **Workaround actual:** Validación estática y fake systemctl del test DEB.
- **Criterios de aceptación:** Install/start/stop/restart/reboot, endpoint y
  capture, hardening efectivo, logs, failure recovery, upgrade/rollback y
  uninstall bajo PID 1 real.
- **Evidencia actual:** `scripts/linux/test-deb-runtime.sh` reemplaza systemctl;
  `docs/phase07/testing-and-limitations.md` dice que el servicio real no fue
  iniciado.
- **Evidencia de validación requerida:** `systemctl show/status`, PID/cgroup,
  security analysis, journald, reboot y lifecycle DEB en VM/host real.
- **Decisión pendiente:** Distro/virtualización del harness y gate de CI/manual.
- **Fase futura sugerida:** Sin fase numerada asignada.
- **Última revisión:** 2026-07-17.

### FW-VAL-LNX-004 — cgroup v2 real delegado

- **Identificador estable:** `FW-VAL-LNX-004`
- **Nombre:** Contención y cleanup de árbol en cgroup real.
- **Área o componente:** LinuxProcessRunner / Capture Node.
- **Estado:** `IMPLEMENTED_NOT_VALIDATED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Validar un leaf privado delegado a `User=wto-capture` con
  `cgroup.procs`, `cgroup.events` y `cgroup.kill` reales.
- **Comportamiento actual:** Unit tests simulan cgroupfs/state machines. La suite
  opt-in puede probar un descendiente `setsid()` sólo si el harness entrega un
  subtree; exige UID 0 y no valida por sí sola
  `User=wto-capture + Delegate=yes` sin CAP_SYS_ADMIN.
- **Impacto:** La contención productiva no está demostrada en la identidad y
  unidad reales; captura/replay/Flent fallan cerrado sin readiness.
- **Motivo por el que no está completa:** No existe harness CI dentro de una
  unidad delegada no-root real.
- **Dependencias:** `FW-VAL-LNX-003` y host con cgroup v2.
- **Riesgos:** Descendientes sobrevivientes, PID reuse, permisos excesivos o
  incapacidad de remover leaf.
- **Workaround actual:** Simulación; prueba manual opt-in cuando el laboratorio
  provee delegación.
- **Criterios de aceptación:** Readiness crea leaf, mueve líder, verifica
  membership, mata descendiente `setsid()`, observa `populated=0`, reapea y
  elimina exactamente una vez bajo usuario real sin CAP_SYS_ADMIN.
- **Evidencia actual:** `test_cgroup.py` simula;
  `tests/linux/test_linux_privileged_opt_in.py` puede saltarse por falta de
  subtree; documentación registra el gap no-root.
- **Evidencia de validación requerida:** PID/cgroup antes/después, permisos,
  UID/capabilities, descendientes reales, timeout/cancelación y cleanup.
- **Decisión pendiente:** Harness permanente y matrices de kernel/systemd.
- **Fase futura sugerida:** Sin fase numerada asignada.
- **Última revisión:** 2026-07-17.

### FW-VAL-LNX-005 — Validación física integral del Capture Node

- **Identificador estable:** `FW-VAL-LNX-005`
- **Nombre:** Gate integrado de Capture Node real.
- **Área o componente:** Capture Node end-to-end.
- **Estado:** `IMPLEMENTED_NOT_VALIDATED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Validación agregada que integra herramientas reales,
  NetworkManager, iw, dumpcap, cgroup, systemd, hardware, rollback y crash
  recovery.
- **Comportamiento actual:** Cada boundary tiene código/tests parciales, pero no
  se ejecutó un escenario físico integrado. Esta entrada no sustituye sus gates:
  depende de `FW-VAL-LNX-001`–`004` y de `FW-SEC-001`.
- **Impacto:** No se puede declarar Capture Node soportado end-to-end aunque los
  componentes simulados pasen.
- **Motivo por el que no está completa:** Falta laboratorio autorizado,
  autorización real y ejecución coordinada de todos los componentes.
- **Dependencias:** `FW-SEC-001`, `FW-VAL-LNX-001`, `002`, `003` y `004`.
- **Riesgos:** Interacciones que no aparecen aisladas: D-Bus cambia durante
  captura, conexión perdida, cgroup cleanup y rollback compiten, o reboot deja
  journal.
- **Workaround actual:** Evidencia fragmentaria de unit/integration simulation y
  runbooks manuales.
- **Criterios de aceptación:** DEB real; systemd PID 1; usuario/capabilities;
  NetworkManager D-Bus; iw; radio dedicada; dumpcap/radiotap; cgroup; captura
  acotada; artifact; success/failure/cancel/crash/reboot; rollback y recovery
  completos.
- **Evidencia actual:** `docs/phase07/testing-and-limitations.md` enumera todos
  estos elementos como pendientes en host Linux descartable.
- **Evidencia de validación requerida:** Evidence bundle único con matriz de
  host/hardware/tools, comandos sanitizados, PCAP/hash, journal, logs,
  cgroups/PIDs y resultados de recuperación.
- **Decisión pendiente:** Laboratorio, hardware mínimo, owner del gate y
  condiciones de soporte.
- **Fase futura sugerida:** Sin fase numerada; gate de cierre físico posterior a
  Fase 07.
- **Última revisión:** 2026-07-17.

### FW-VAL-WIN-002 — Validación física integral del agente Windows

- **Identificador estable:** `FW-VAL-WIN-002`
- **Nombre:** Matriz real Windows/Wi-Fi/service/packaging.
- **Área o componente:** Agente Windows.
- **Estado:** `IMPLEMENTED_NOT_VALIDATED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Validar Native Wi-Fi, inventario, control local, service,
  IPC, credenciales y packaging sobre hardware/OS reales.
- **Comportamiento actual:** La documentación marca el estado general
  `NOT RUN`. GitHub Actions no demuestra radio, WlanSvc, Npcap, 6 GHz,
  sleep/reboot ni hardware Wi-Fi.
- **Impacto:** No existe matriz de soporte física para Windows 10/11,
  localización, drivers y adapters.
- **Motivo por el que no está completa:** No se ejecutó
  `scripts/windows/validate-real-hardware.ps1` sobre la matriz documentada.
- **Dependencias:** Hosts Windows 10/11, radios reales, LocalService y paquetes.
- **Riesgos:** Permisos/location, localización, sleep/resume, service account o
  driver cambian comportamiento.
- **Workaround actual:** Unit/native CI sin afirmación de hardware.
- **Criterios de aceptación:** Checklist completo de
  `docs/phase06/real-hardware-validation.md`, incluyendo install/upgrade/
  rollback/uninstall/purge.
- **Evidencia actual:** Ese documento declara `Estado general: NOT RUN`.
- **Evidencia de validación requerida:** Evidence bundle por OS/idioma/NIC/
  driver con WlanSvc, radios/bandas, sleep/reboot, LocalService, IPC, secrets y
  packaging.
- **Decisión pendiente:** Matriz mínima de hardware, idiomas y versiones.
- **Fase futura sugerida:** Sin fase futura asignada.
- **Última revisión:** 2026-07-17.

## 4. Funcionalidades disponibles sólo manualmente

### FW-MAN-LNX-001 — Pruebas Linux privilegiadas opt-in

- **Identificador estable:** `FW-MAN-LNX-001`
- **Nombre:** Suite privilegiada de laboratorio Linux.
- **Área o componente:** Validación Capture Node/cgroup.
- **Estado:** `MANUAL_ONLY`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ejecutar tests que requieren root, host descartable, red
  autorizada, NIC dedicada y consola local.
- **Comportamiento actual:** Se habilitan sólo con
  `WTO_RUN_PRIVILEGED_LINUX_TESTS=1`. El sentinel exige UID 0; la prueba real de
  cgroup se salta si no existe subtree v2 delegado. La suite no implementa por
  sí sola las transiciones de NIC: remite al runbook externo.
- **Impacto:** El CI normal no cubre efectos privilegiados ni hardware.
- **Motivo por el que no está completa:** Automatizarlas en runners comunes
  sería inseguro y no hay harness de lab permanente.
- **Dependencias:** Laboratorio descartable y runbooks.
- **Riesgos:** Cambiar interfaz de management, perder conexión o afectar una red
  no autorizada.
- **Workaround actual:** Ejecución manual controlada con opt-in explícito.
- **Criterios de aceptación:** Harness aislado, sentinel, inventario de host,
  artefactos de evidencia, cleanup y resultado no skipped para cada gate
  seleccionado.
- **Evidencia actual:** `tests/linux/test_linux_privileged_opt_in.py` y
  `docs/phase07/testing-and-limitations.md`.
- **Evidencia de validación requerida:** Comando exacto, host descartable,
  markers ejecutados/no skipped y cleanup verificado.
- **Decisión pendiente:** Si crear runner/harness dedicado y qué tests puede
  automatizar.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-17.

### FW-MAN-LNX-002 — Recuperación de interfaz tras rollback incompleto

- **Identificador estable:** `FW-MAN-LNX-002`
- **Nombre:** Recuperación de NIC de captura bloqueada.
- **Área o componente:** Capture Node / rollback.
- **Estado:** `MANUAL_ONLY`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Restaurar una interfaz cuando queda journal o
  `rollback_incomplete`.
- **Comportamiento actual:** El estado bloquea nuevas capturas. El operador debe
  intervenir si una mutación falló o la evidencia quedó ambigua. Cuando todas
  las mutaciones fueron confirmadas y sólo falta una observación completa, el
  marker queda `ROLLBACK_VERIFICATION_PENDING` y un retry ejecuta únicamente
  verificación read-only, sin repetir mutadores. Para múltiples conexiones,
  cada secundaria y la primaria final tienen intent/confirmación durable por
  UUID; un paso `planned` se resuelve observando antes de decidir repetir. No
  hay reboot ni reinstalación automática de drivers.
- **Impacto:** El Capture Node queda fuera de servicio hasta intervención
  segura.
- **Motivo por el que no está completa:** Automatizar tras una falla no
  representable puede agravar pérdida de conectividad.
- **Dependencias:** Journal íntegro, consola local, herramientas y administrador
  del laboratorio.
- **Riesgos:** Usar valores de ejemplo, borrar journal antes de verificar o
  tocar la interfaz de management.
- **Workaround actual:** Runbook manual oficial.
- **Criterios de aceptación:** Herramienta futura sólo si puede verificar
  identidad/estado, preservar evidencia, aplicar pasos idempotentes y mantener
  fail-closed ante ambigüedad.
- **Evidencia actual:** `docs/phase07/interface-recovery-runbook.md`.
- **Evidencia de validación requerida:** Casos reales de rollback parcial,
  driver failure, journal preservado, estado final y doctor sin `BLOCKED`.
- **Decisión pendiente:** Mantener manual o construir herramienta offline
  asistida.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-18.

### FW-MAN-LNX-003 — Purga física de cuarentenas

- **Identificador estable:** `FW-MAN-LNX-003`
- **Nombre:** Eliminación física offline de objetos en cuarentena.
- **Área o componente:** Filesystem seguro / artifacts / secretos / journals.
- **Estado:** `MANUAL_ONLY`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Liberar físicamente espacio después de una cuarentena lógica,
  bajo condiciones controladas.
- **Comportamiento actual:** El flujo online sólo renombra a cuarentena,
  revalida identidad y reporta `physical_delete_pending`. No ejecuta unlink
  físico online ni purger remoto/automático. La purga requiere servicio detenido
  e inspección administrativa.
- **Impacto:** Cuarentenas siguen consumiendo disco.
- **Motivo por el que no está completa:** Linux no permite unlink seguro de
  archivo regular por descriptor frente a actor hostil con mismo UID; borrar
  por nombre reabre una carrera.
- **Dependencias:** Policy offline, inventario, owner/inode/hash y backup cuando
  aplique.
- **Riesgos:** Borrar reemplazo ajeno, evidencia o estado todavía referenciado.
- **Workaround actual:** Mantenimiento offline/manual.
- **Criterios de aceptación:** Herramienta futura con servicio detenido,
  selección explícita, identidad revalidada, dry-run, límites, audit log y
  reporte exacto de bytes liberados.
- **Evidencia actual:** `docs/phase07/installation-and-distributions.md`,
  `security-and-permissions.md` y `secure_fs.py`.
- **Evidencia de validación requerida:** Symlink/hardlink/replacement/EXDEV,
  crash, dry-run, referencia SQLite y medición real de espacio.
- **Decisión pendiente:** Si automatizar herramienta offline, política de
  retención y autoridad.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-17.

## 5. Compatibilidad y recuperación de formatos históricos

### FW-HIST-LNX-001 — encrypted_file con store-state pero sin completion guard

- **Identificador estable:** `FW-HIST-LNX-001`
- **Nombre:** Recuperación de stores históricos sin
  `.store-completion-guard`.
- **Área o componente:** Agente Linux / SecretStore encrypted_file.
- **Estado:** `RECOVERY_REQUIRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Recuperar o migrar de forma offline un store existente que
  contiene `.store-state` pero no el completion guard del formato actual.
- **Comportamiento actual:** El store detecta la combinación histórica, no crea
  el guard online, publica `BLOCKED_COMPLETION_GUARD_MISSING` y rechaza
  operaciones. El bloqueo es deliberado.
- **Impacto:** El agente no puede leer/escribir secrets con ese store hasta
  recuperación segura.
- **Motivo por el que no está completa:** No existe migración online confiable:
  crear un guard ausente podría aceptar como completo un estado cuya última
  mutación no puede demostrarse.
- **Dependencias:** Herramienta offline, backup inmutable, inspección de slots,
  ciphertext/key y formato versionado.
- **Riesgos:** Promover store inconsistente, perder secretos o sobrescribir
  evidencia.
- **Workaround actual:** Detener servicio, preservar store y escalar a
  recuperación manual; no agregar el archivo a mano.
- **Criterios de aceptación:** Tool offline read-only/dry-run primero, backup,
  diagnóstico inequívoco, migración atómica, rollback, audit trail y rechazo de
  estados ambiguos/corruptos.
- **Evidencia actual:** `secret_store.py` distingue
  `completion_guard_missing`; el test
  `test_existing_store_never_bootstraps_a_missing_completion_file_online`
  elimina el guard y comprueba bloqueo sin recrearlo.
- **Evidencia de validación requerida:** Vectores históricos sanos/corruptos,
  crash en cada paso, key correcta/incorrecta, backup/restore y store operativo
  sólo después de verificación.
- **Decisión pendiente:** Diseñar herramienta y política de aprobación; decidir
  si se migra o sólo se exportan/reemiten credenciales.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-17.

### FW-HIST-LNX-002 — Journals NetworkManager históricos sin identidad suficiente

- **Identificador estable:** `FW-HIST-LNX-002`
- **Nombre:** Recuperación de journals basados en nombres visibles o sin
  primaria demostrable.
- **Área o componente:** Capture Node / journal de interfaz.
- **Estado:** `RECOVERY_REQUIRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Tratar snapshots v1 que identifican conexiones
  NetworkManager sólo por display name, o journals históricos con conexiones
  activas pero sin UUID primario autoritativo.
- **Comportamiento actual:** Journals desconectados sin conexión pueden
  clasificarse, pero se preservan como recovery journal. Si contienen nombres
  de conexión o no permiten demostrar cuál UUID era primario, la validación
  lanza “manual recovery”; rollback productivo sólo usa UUID canónico y nunca
  inventa la primaria.
- **Impacto:** No se puede reactivar automáticamente y de forma confiable la
  conexión original desde un nombre mutable/no único ni preservar la primaria
  cuando el journal no la registró.
- **Motivo por el que no está completa:** Los nombres visibles no son identidad
  estable, no hay mapeo histórico confiable a UUID y el estado actual no prueba
  retrospectivamente qué conexión era la primaria.
- **Dependencias:** Tool offline, estado actual de NetworkManager, evidencia del
  journal y aprobación humana.
- **Riesgos:** Levantar la conexión equivocada o perder la interfaz de
  management.
- **Workaround actual:** Recuperación manual con servicio detenido y consola
  local; preservar el journal.
- **Criterios de aceptación:** Tool futura sólo propone candidatos con
  evidencia, nunca autoelige ante ambigüedad; usa UUID para mutar, conserva
  original y registra decisión/resultado.
- **Evidencia actual:** `capture.py::_validate_legacy_journal_state` explica la
  limitación; `test_capture_commands.py` prueba que nombre requiere manual y
  rollback usa sólo UUID.
- **Evidencia de validación requerida:** Nombres duplicados/renombrados,
  conexión inexistente, UUID único, primaria ausente, host desconectado y
  rollback verificado.
- **Decisión pendiente:** Alcance de herramienta offline y nivel de asistencia
  permitido.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-18.

### FW-HIST-DB-001 — Downgrade de SQLite local

- **Identificador estable:** `FW-HIST-DB-001`
- **Nombre:** Recuperación al volver a un schema SQLite anterior.
- **Área o componente:** Agente desktop / persistencia local.
- **Estado:** `RECOVERY_REQUIRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Volver a una versión anterior del agente sin abrir un schema
  que el binario viejo no comprende.
- **Comportamiento actual:** Las migraciones son forward-only; no hay downgrade
  DDL. Rollback requiere detener el servicio y restaurar el backup verificado
  previo. El binario anterior debe fallar cerrado.
- **Impacto:** Sin backup compatible no hay downgrade online soportado.
- **Motivo por el que no está completa:** Revertir DDL/semántica local puede
  perder estados, journals u outboxes.
- **Dependencias:** Backup API, `quick_check`, bundle anterior y runbook.
- **Riesgos:** Borrar base para ocultar incompatibilidad, perder outbox o
  ejecutar efectos duplicados.
- **Workaround actual:** Restore manual del backup pre-upgrade.
- **Criterios de aceptación:** Cualquier herramienta futura debe verificar
  versión/checksum/backup, documentar pérdida posible, mantener fail-closed y
  probar upgrade/rollback por cada ventana soportada.
- **Evidencia actual:** Documentación de recuperación de Fases 05–07 declara
  forward-only y restore de backup; scripts Linux/Windows exigen confirmación.
- **Evidencia de validación requerida:** Base vacía, N-1→N, rollback con backup,
  backup corrupto/incompatible y preservación de outboxes/journals.
- **Decisión pendiente:** Ventana de rollback soportada y si habrá migradores
  offline específicos.
- **Fase futura sugerida:** Fase 22 contempla migraciones/compatibilidad de
  plugins; no hay fase exacta para SQLite core.
- **Última revisión:** 2026-07-17.

## 6. Limitaciones dependientes del entorno

### FW-ENV-LNX-001 — Matriz de distribuciones Linux

- **Identificador estable:** `FW-ENV-LNX-001`
- **Nombre:** Soporte validado por distribución.
- **Área o componente:** Agente/packaging Linux.
- **Estado:** `ENVIRONMENT_LIMITED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Declarar soporte sólo después de validar runtime,
  dependencias, packaging, systemd y hardware por distro.
- **Comportamiento actual:** Ubuntu 24.04 es objetivo DEB con CI
  estática/simulada; Ubuntu 22.04 y Debian 12 requieren Python 3.12
  administrado; Debian 13 está previsto; Fedora/RHEL carece de RPM.
- **Impacto:** Portabilidad de diseño no equivale a soporte en esas
  distribuciones.
- **Motivo por el que no está completa:** No existe matriz física/runtime
  aprobada para todas.
- **Dependencias:** Python 3.12+, wheels, DEB/RPM, systemd, kernel, tools y
  hardware.
- **Riesgos:** Dependencias incompatibles, primitives ausentes, SELinux o
  drivers distintos.
- **Workaround actual:** Target inicial Ubuntu 24.04 y fail-closed de
  readiness/providers.
- **Criterios de aceptación:** Matriz por distro/version/arch con install,
  service PID 1, upgrade/rollback, tools y hardware aplicable.
- **Evidencia actual:** Tabla de
  `docs/phase07/installation-and-distributions.md`.
- **Evidencia de validación requerida:** Hosts/VMs reales por target, package
  lifecycle y evidence bundle reproducible.
- **Decisión pendiente:** Distros, versiones y arquitecturas que serán
  oficialmente soportadas.
- **Fase futura sugerida:** Fase 24 para distribución; la selección exacta está
  abierta.
- **Última revisión:** 2026-07-17.

### FW-ENV-LNX-002 — Dependencia de renameat2

- **Identificador estable:** `FW-ENV-LNX-002`
- **Nombre:** Publicación/retirement seguro con `renameat2`.
- **Área o componente:** Filesystem seguro Linux.
- **Estado:** `ENVIRONMENT_LIMITED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Ejecutar staging y encrypted_file sólo cuando kernel/libc
  proveen `RENAME_NOREPLACE` y, para update, `RENAME_EXCHANGE`.
- **Comportamiento actual:** La ausencia falla cerrado; no hay fallback con
  hardlink/unlink o rename con overwrite.
- **Impacto:** Artifacts y secret store encrypted_file no están disponibles en
  entornos sin esas primitivas.
- **Motivo por el que no está completa:** Los fallbacks habituales no conservan
  las garantías de identidad/no-overwrite requeridas.
- **Dependencias:** Kernel, libc/filesystem y semantics locales.
- **Riesgos:** Claim de portabilidad excesivo o degradación insegura.
- **Workaround actual:** Usar host compatible; no forzar fallback.
- **Criterios de aceptación:** Mantener limitación explícita o diseñar una
  primitiva alternativa con garantías equivalentes y pruebas de carrera/crash.
- **Evidencia actual:** `docs/phase07/installation-and-distributions.md` y
  `security-and-permissions.md`.
- **Evidencia de validación requerida:** Filesystems/kernels objetivo,
  unsupported syscall, EXDEV, reemplazo concurrente y crash durability.
- **Decisión pendiente:** Baseline mínimo de kernel/libc/filesystem o inversión
  en alternativa.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-17.

### FW-ENV-SRV-001 — Portabilidad del servidor fuera del entorno inicial

- **Identificador estable:** `FW-ENV-SRV-001`
- **Nombre:** Validación del servidor en Linux, macOS y cloud.
- **Área o componente:** Server deployment.
- **Estado:** `ENVIRONMENT_LIMITED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Demostrar que los servicios OCI conservan comportamiento y
  contratos fuera de Windows 11 + Docker Desktop/WSL2.
- **Comportamiento actual:** La arquitectura exige portabilidad y CI corre
  contenedores Linux, pero README la describe como futura; no hay matriz
  operativa macOS/cloud ni topología distribuida validada.
- **Impacto:** Diseño portable no es evidencia de soporte operacional en cada
  entorno.
- **Motivo por el que no está completa:** No se ejecutaron install/runbook,
  persistence, backup/restore y carga por target.
- **Dependencias:** Container runtime, networking, storage, TLS/secrets y
  `FW-OPS-003`.
- **Riesgos:** Filesystem/networking/secret management divergentes.
- **Workaround actual:** Entorno inicial documentado de Windows 11/WSL2 o Linux
  de desarrollo.
- **Criterios de aceptación:** Checkout limpio, start/stop, migrations, smoke,
  persistence, backup/restore y contratos idénticos por target aprobado.
- **Evidencia actual:** README y ADR-0001 declaran portabilidad obligatoria pero
  futura; no hay workflows macOS/cloud del servidor.
- **Evidencia de validación requerida:** Evidence bundles por runtime/OS/cloud,
  sin paths/APIs exclusivos del host.
- **Decisión pendiente:** Targets y orden de soporte.
- **Fase futura sugerida:** Sin fase concreta; Prompt 26 valida el target
  Windows/WSL2, no toda la matriz.
- **Última revisión:** 2026-07-17.

### FW-ENV-SCALE-001 — Capacidad, retención, RPO y RTO medidos

- **Identificador estable:** `FW-ENV-SCALE-001`
- **Nombre:** Validación de hipótesis operativas.
- **Área o componente:** Servidor / observabilidad / storage.
- **Estado:** `ENVIRONMENT_LIMITED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Medir agentes, concurrencia, ingestión, PCAP, retención y
  recovery antes de tratarlos como capacidad o SLA.
- **Comportamiento actual:** 500 agentes, 100 online, 25 tráficos, 10 campañas,
  retenciones y RPO/RTO son hipótesis/objetivos provisionales; no benchmarks.
- **Impacto:** No se debe dimensionar producción ni prometer SLA con esos
  números.
- **Motivo por el que no está completa:** Aún faltan traffic/telemetry/artifacts
  productivos y pruebas de carga/restore.
- **Dependencias:** `FW-TEL-001`, `FW-TRF-001`, `FW-ART-001` y `FW-OPS-003`.
- **Riesgos:** Saturación, pérdida de datos o costos subestimados.
- **Workaround actual:** Tratar valores como límites de planificación y
  monitorear el entorno de desarrollo.
- **Criterios de aceptación:** Workloads representativos, sample sizes,
  percentiles, bottlenecks, restore y revisión documentada de límites/RPO/RTO.
- **Evidencia actual:** ADR-0015 y
  `docs/architecture/quality-attributes-and-assumptions.md` los llaman hipótesis
  a medir.
- **Evidencia de validación requerida:** Load/soak, agent storm, ingest,
  traffic/artifact concurrency, storage growth y restore cronometrado.
- **Decisión pendiente:** Objetivos, hardware de referencia y criterio de
  aprobación.
- **Fase futura sugerida:** Fases 23 y 26 incluyen load y restore.
- **Última revisión:** 2026-07-17.

## 7. Decisiones pendientes del responsable del proyecto

Las siguientes entradas no reemplazan las decisiones individuales de cada
capacidad. Agrupan elecciones transversales que bloquean varias entradas.

### FW-DEC-001 — Secuencia de habilitación privilegiada

- **Identificador estable:** `FW-DEC-001`
- **Nombre:** Orden entre grant, Capture Node físico y replay.
- **Área o componente:** Producto / seguridad / laboratorio.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Decidir si primero se implementa el grant server-side, se
  construye el laboratorio físico o se desarrolla un flujo coordinado.
- **Comportamiento actual:** `FW-SEC-001` bloquea producción y
  `FW-VAL-LNX-005` carece de evidencia física; tcpreplay es simulación.
- **Impacto:** Sin secuencia aprobada no hay camino de habilitación productiva
  verificable.
- **Motivo por el que no está completa:** Decisión transversal no registrada.
- **Dependencias:** `FW-SEC-001`, `FW-CAP-003`, `FW-VAL-LNX-005` y
  `FW-REPLAY-001`.
- **Riesgos:** Validar con bypass inseguro o implementar contrato sin entorno
  para probarlo.
- **Workaround actual:** Mantener fail-closed y simulación.
- **Criterios de aceptación:** Decisión del responsable con orden, owners,
  gates y evidencia; sin fecha inventada.
- **Evidencia actual:** Dependencias citadas y default productivo unavailable.
- **Evidencia de validación requerida:** Acta/registro y actualización de
  entradas afectadas.
- **Decisión pendiente:** La secuencia misma.
- **Fase futura sugerida:** Fases 10/20 son referencias, no decisión.
- **Última revisión:** 2026-07-17.

### FW-DEC-002 — Alcance de herramientas offline de recuperación

- **Identificador estable:** `FW-DEC-002`
- **Nombre:** Toolkit offline para stores, journals y cuarentenas.
- **Área o componente:** Operaciones / recovery.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Decidir si crear una herramienta común o utilidades separadas
  para `FW-HIST-LNX-001`, `FW-HIST-LNX-002` y `FW-MAN-LNX-003`.
- **Comportamiento actual:** Existen fail-closed y runbooks; no herramientas
  automáticas.
- **Impacto:** Recuperaciones siguen dependiendo de especialistas y pueden ser
  lentas.
- **Motivo por el que no está completa:** No se definieron autoridad, UX,
  formatos ni garantías.
- **Dependencias:** Backup, dry-run, identidad de archivos, audit trail y
  versiones de formato.
- **Riesgos:** Una herramienta demasiado genérica podría destruir evidencia o
  promover estado ambiguo.
- **Workaround actual:** Recuperación manual/offline.
- **Criterios de aceptación:** Decisión de alcance, threat model, formato de
  evidencia y regla explícita de no mutar ante ambigüedad.
- **Evidencia actual:** Entradas de recovery relacionadas.
- **Evidencia de validación requerida:** Decision record y test plan con
  fixtures históricos/corruptos.
- **Decisión pendiente:** Tool única vs separadas y operaciones autorizadas.
- **Fase futura sugerida:** Sin fase asignada.
- **Última revisión:** 2026-07-17.

### FW-DEC-003 — Matriz oficial de soporte y distribución

- **Identificador estable:** `FW-DEC-003`
- **Nombre:** OS, distro, hardware y canales soportados.
- **Área o componente:** Producto / release.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Seleccionar targets que pasarán de “diseño/condicional” a
  soporte oficial.
- **Comportamiento actual:** Hay referencias amplias y packaging parcial, pero
  no matriz física aprobada.
- **Impacto:** Operadores no tienen una frontera única de soporte.
- **Motivo por el que no está completa:** Falta decisión basada en costo y
  evidencia.
- **Dependencias:** `FW-ENV-LNX-001`, `FW-VAL-WIN-002`,
  `FW-VAL-LNX-005`, mobile y packaging.
- **Riesgos:** Declarar soporte por documentación del proveedor o excluir una
  plataforma relevante sin consulta.
- **Workaround actual:** Publicar estados condicionales/fail-closed por entorno.
- **Criterios de aceptación:** Lista versionada de OS/distro/hardware/tool,
  política de EOL y evidence gate.
- **Evidencia actual:** Matrices actuales se declaran iniciales/condicionales.
- **Evidencia de validación requerida:** Decisión del responsable y vínculos a
  evidence bundles.
- **Decisión pendiente:** Targets y niveles de soporte.
- **Fase futura sugerida:** Fase 24 contempla matriz de soporte.
- **Última revisión:** 2026-07-17.

### FW-DEC-004 — Priorización del backlog posterior a Fase 07

- **Identificador estable:** `FW-DEC-004`
- **Nombre:** Orden de capacidades de Fases 08–26.
- **Área o componente:** Producto / roadmap.
- **Estado:** `DEFERRED`.
- **Prioridad:** `TO_BE_DECIDED`.
- **Descripción:** Confirmar el orden de producto del backlog documentado sin
  asumir que el número de prompt equivale a prioridad o fecha.
- **Comportamiento actual:** `PROMPT_INDEX.md` define una secuencia técnica; no
  asigna fechas ni prioridades CRITICAL/HIGH/MEDIUM/LOW.
- **Impacto:** Salvo 40 MHz, este inventario no puede priorizar unilateralmente
  capacidades relevantes.
- **Motivo por el que no está completa:** Falta decisión explícita del
  responsable.
- **Dependencias:** Entradas `FW-MOB-*`, `FW-NET-*`, `FW-TRF-*`,
  `FW-TEL-001`, `FW-CAMP-001`, `FW-UI-001`, `FW-ART-001`,
  `FW-INT-001`, `FW-PLUG-001` y `FW-SECOPS-001`.
- **Riesgos:** Confundir dependencia técnica con prioridad de producto o cerrar
  una fase haciendo desaparecer trabajo.
- **Workaround actual:** Mantener `TO_BE_DECIDED` y conservar todas las
  entradas.
- **Criterios de aceptación:** Decisión registrada por capacidad o grupo, con
  motivo e impacto; ninguna fecha se infiere.
- **Evidencia actual:** `prompts/PROMPT_INDEX.md` y prioridades sin asignar de
  este documento.
- **Evidencia de validación requerida:** Registro aprobado y actualización de
  prioridades.
- **Decisión pendiente:** Orden/prioridad del backlog.
- **Fase futura sugerida:** Fases 08–26 ya documentadas; no son compromisos.
- **Última revisión:** 2026-07-17.

## Registro de decisiones

### Decisión vigente — Permisos de artifacts aprobados para replay

- **Fecha:** 2026-07-18, fecha de registro en este documento.
- **Capacidad:** `FW-REPLAY-002` — provisioning administrativo de artifacts de
  replay.
- **Alternativas consideradas:** Owner del usuario del servicio con root
  `0700` y archivo `0400/0600`; root owner con grupo Linux dedicado y `0440`.
- **Decisión del responsable:** Fase 07 usa exclusivamente owner igual al
  usuario efectivo del servicio, directorio `0700`, archivo regular `0400` o
  `0600` y `st_nlink == 1`.
- **Motivo:** Mantener una autoridad de permisos única y comprobable sin crear
  ahora lifecycle de grupo/provisioning administrativo.
- **Impacto:** Root owner, grupo dedicado y `0440` se rechazan y permanecen
  diferidos en `FW-REPLAY-002`.
- **Fase prevista:** Sin fase numerada asignada.
- **Evidencia requerida para cerrarla:** Los criterios de `FW-REPLAY-002`.

### Decisión vigente — Captura completa en 40 MHz

- **Fecha:** 2026-07-17, fecha de registro en este documento.
- **Capacidad:** `FW-CAP-001` — captura completa IEEE 802.11 en 40 MHz.
- **Alternativas consideradas:** Incluirla en el cierre inmediato de Fase 07;
  posponerla conservando prioridad; reducir el alcance a 20 MHz del primario.
- **Decisión del responsable:** La captura de 40 MHz es importante; no se
  implementará dentro del cierre inmediato de Fase 07 y permanece como
  desarrollo prioritario. Capturar 20 MHz del primario no se aceptará como
  equivalencia.
- **Motivo:** El cierre inmediato no incorpora el modelo, policy, journal,
  rollback y validación física específicos de HT40.
- **Impacto:** `FW-CAP-001` permanece `NOT_IMPLEMENTED` y `HIGH`; no se elimina
  ni se reclasifica como mejora menor.
- **Fase prevista:** No se asigna fase numerada ni fecha de implementación.
- **Evidencia requerida para cerrarla:** Todos los criterios y evidencia física
  definidos en `FW-CAP-001`.

También queda vigente la regla de que, antes de posponer, reducir, eliminar o
declarar fuera de alcance otra capacidad relevante, se consultará al
responsable y se registrará aquí la decisión.

### Plantilla para decisiones futuras

Copiar esta plantilla sin eliminar decisiones anteriores:

```markdown
### Decisión — <título>

- **Fecha:** <fecha real de la decisión>
- **Capacidad:** <identificador estable y nombre>
- **Alternativas consideradas:** <alternativas evaluadas>
- **Decisión del responsable:** <decisión explícita>
- **Motivo:** <fundamento>
- **Impacto:** <entradas, contratos, operación y riesgos afectados>
- **Fase prevista:** <fase sólo si ya existe evidencia; de lo contrario, sin asignar>
- **Evidencia requerida para cerrarla:** <evidence bundle y criterios verificables>
```

## 8. Elementos completados posteriormente, conservados como historial

### FW-VAL-WIN-001 — PowerShell 7

- **Identificador estable:** `FW-VAL-WIN-001`
- **Nombre:** Provider de inventario bajo PowerShell 7.
- **Área o componente:** Agente Windows.
- **Estado anterior:** `IMPLEMENTED_NOT_VALIDATED`.
- **Estado de cierre:** `COMPLETED`, como marcador histórico y no como estado
  de la taxonomía de pendientes.
- **Prioridad anterior:** `TO_BE_DECIDED`.
- **Descripción:** Ejecutar y validar el script fijo de inventario en
  PowerShell Core 7, además del baseline Windows PowerShell 5.1.
- **Comportamiento previo:** CI diagnosticaba explícitamente 5.1. Existía
  fixture para 7 y un test nativo opcional, pero se marcaba skipped cuando
  `pwsh` no estaba instalado; no había evidencia de ejecución aprobada de
  PowerShell 7.
- **Impacto previo:** No podía declararse PowerShell 7 dentro de la matriz
  validada.
- **Motivo por el que no estaba completa:** El runner observado sólo aportaba
  5.1.
- **Dependencias para el cierre:** Host Windows con `pwsh` 7 instalado y las
  mismas policies/APIs.
- **Riesgos evaluados:** Diferencias de edition/encoding/CIM, timeouts o
  cleanup.
- **Workaround previo:** Windows PowerShell 5.1, baseline ya ejercitado.
- **Criterios de aceptación originales:** Mismos siete providers, budgets, JSON
  estricto, marker/handles/Job Objects, diagnostics y cleanup bajo `pwsh` 7.
- **Evidencia previa al cierre:** `.github/workflows/ci.yml` nombraba
  “PowerShell 5.1”;
  `test_windows_native.py::test_powershell_7_inventory_when_available` hacía
  skip si faltaba `pwsh`.
- **Evidencia de validación requerida originalmente:** Versión exacta,
  stdout/stderr, diagnostics, timeouts y cero procesos/streams remanentes en
  Windows real.
- **Decisión pendiente previa:** Versiones 7.x soportadas y si sería provider
  seleccionable o sólo matriz de compatibilidad.
- **Fase futura sugerida previamente:** Sin fase futura asignada; Fase 06 la
  define como matriz adicional.
- **Fecha real de cierre:** 2026-07-17.
- **Decisión de cierre y responsable:** El responsable del proyecto indicó
  registrar PowerShell 7 como validado a partir de la evidencia local detallada
  a continuación. La capacidad deja de ser trabajo pendiente.
- **Versión/release o commit verificable:** No se atribuye el cierre a un
  release, commit ni job de CI remoto; la evidencia corresponde a la ejecución
  local informada sobre la rama
  `phase/07-linux-agent-and-capture-node`.
- **Evidencia ejecutada:** En Windows local, PowerShell 7.6.3 con
  `PSEdition=Core`; Python 3.13.13 desde
  `C:\Dev\WiFi-Test-Orchestrator\.tmp\phase07-native\Scripts\python.exe` y
  pytest 8.4.1. Desde `C:\Dev\WiFi-Test-Orchestrator\agents\desktop` se ejecutó
  `python -B -m pytest tests/windows -m windows -vv -p no:cacheprovider`: 56
  tests collected, 56 passed, 0 failed, 0 skipped, en aproximadamente 107.45
  segundos. El test
  `tests/windows/test_windows_native.py::test_powershell_7_inventory_when_available`
  se ejecutó y pasó.
- **Tipo y alcance de la validación:** Suite nativa automatizada en un host
  Windows local con el runtime disponible; valida el provider de inventario con
  PowerShell 7.6.3 Core. No constituye validación física integral del agente ni
  de toda la plataforma Windows.
- **Limitaciones residuales o entradas sucesoras:** La evidencia no se extiende
  a otras versiones de PowerShell 7 ni a CI remoto. Windows PowerShell 5.1
  continúa como baseline separado y no fue reemplazado. Esta conclusión no
  modifica ni cierra `FW-VAL-WIN-002`.
- **Última revisión:** 2026-07-17.

Cuando una capacidad se complete, mover aquí su entrada íntegra y agregar:

- **Estado anterior**
- **Estado de cierre:** `COMPLETED` como marcador histórico, sin incorporarlo a
  la taxonomía de pendientes.
- **Fecha real de cierre**
- **Decisión de cierre y responsable**
- **Versión/release o commit verificable**
- **Evidencia ejecutada**, distinguiendo automatización de validación física.
- **Limitaciones residuales o entradas sucesoras**

Una entrada sólo puede cerrarse cuando cumple sus criterios de aceptación y
evidencia requerida. Implementar código, pasar tests simulados o eliminar un
skip no es suficiente si la entrada exige hardware o entorno real.
