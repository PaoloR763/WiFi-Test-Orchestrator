# Matriz multidimensional de capabilities

## Carácter del documento

Esta matriz es una evaluación arquitectónica inicial. Los identificadores y
descripciones no son contratos normativos. Toda afirmación depende de versión
del sistema operativo, hardware, driver, permisos, entitlements y APIs
disponibles en el dispositivo concreto.

La disponibilidad observada en una ejecución puede cambiar aunque la
factibilidad técnica general no cambie. Esa situación se informa con `reason`
y no alterando silenciosamente otra dimensión.

## Identificadores conceptuales iniciales

- `wifi.connection.read`
- `wifi.scan`
- `wifi.rssi.read`
- `network.icmp.ping`
- `network.tcp.probe`
- `network.http.probe`
- `traffic.tcp.throughput`
- `traffic.udp.throughput`
- `traffic.http.download`
- `traffic.http.upload`
- `traffic.latency_under_load`
- `capture.ip`
- `capture.ieee80211.monitor`
- `traffic.pcap.replay`
- `execution.background.continuous`

Su versión, naming definitivo y forma de referencia se decidirán en Fase 04.

## Dimensiones independientes

| Dimensión | Pregunta que responde | Regla |
|---|---|---|
| `technical_support` | ¿La plataforma puede realizar la función bajo qué condiciones? | Describe factibilidad, no implementación ni permiso actual |
| `implementation_status` | ¿Existe en este producto y en qué ola se prevé? | No se deduce de soporte técnico |
| `permission_requirement` | ¿Qué autorización del OS, rol o entitlement podría requerirse? | Se evalúa en runtime y puede cambiar por versión |
| `user_interaction` | ¿La persona debe intervenir o mantener foreground? | No se mezcla con permisos ni background |
| `background_execution` | ¿Qué continuidad permite el lifecycle? | Describe restricciones, no garantía de scheduling |
| `provider` | ¿Qué adapter, plugin o stack implementa la función? | Puede haber más de uno; no cambia el capability ID |
| `limitations` | ¿Qué límites y condiciones adicionales aplican? | Valores efectivos se resuelven por política y reserva |

No se define una enumeración cerrada para ninguna dimensión en Fase 01.

## Resumen de cobertura

La tabla siguiente sólo orienta navegación; no reemplaza las dimensiones
detalladas.

| Área | Windows | Linux | Android | iOS | Capture Node |
|---|---|---|---|---|---|
| Wi-Fi endpoint | [Detalle](#windows) | [Detalle](#linux) | [Detalle](#android) | [Detalle](#ios) | [Detalle](#capture-node) |
| Probes de red | [Detalle](#windows) | [Detalle](#linux) | [Detalle](#android) | [Detalle](#ios) | [Detalle](#capture-node) |
| Tráfico | Primera ola planificada | Primera ola planificada | Contrato contemplado; implementación diferida | Contrato contemplado; implementación diferida | Sólo con rol adicional autorizado |
| Captura y replay | Captura IP condicionada | Captura condicionada | Captura IP limitada y condicionada | Sin captura genérica prometida | Rol especializado |
| Background continuo | Windows Service previsto | systemd previsto | Foreground Service sujeto al OS | No prometido | systemd previsto |

## Windows

Cada descripción de soporte de esta tabla está condicionada por edición y
versión de Windows, hardware, driver, permisos, políticas y APIs disponibles.
Nada está implementado todavía.

| Capability | technical_support | implementation_status | permission_requirement | user_interaction | background_execution | provider | limitations |
|---|---|---|---|---|---|---|---|
| `wifi.connection.read` | Previsto con interfaz WLAN y API compatibles | Primera ola planificada | Acceso del servicio y políticas del host | No prevista en operación normal | Consultas periódicas desde Windows Service | Windows Wi-Fi OS adapter por definir | Sólo conexión local actual; `reason` si no hay asociación o dato |
| `wifi.scan` | Previsto si adapter y driver permiten scan | Primera ola planificada | Puede estar restringido por política o contexto del servicio | No prevista normalmente | Posible, sujeto a throttling y comportamiento del driver | Windows Wi-Fi OS adapter por definir | El scan activo puede ser costoso; resultados no equivalen a monitor capture |
| `wifi.rssi.read` | Condicionado a lo que exponga la API; puede ser calidad aproximada y no dBm directo | Primera ola planificada | Igual que lectura de conexión | No prevista | Muestreo sujeto a asociación y API | Windows Wi-Fi OS adapter por definir | Fuente y unidad determinan comparabilidad; no convertir calidad a RSSI sin evidencia |
| `network.icmp.ping` | Posible si red, firewall y API/provider lo permiten | Primera ola planificada | Puede requerir privilegio o binario allowlisted | No prevista | Posible desde servicio dentro de política | ICMP probe por definir | Un destino puede bloquear ICMP; TCP/HTTP no son mediciones equivalentes |
| `network.tcp.probe` | Previsto con sockets del OS | Primera ola planificada | Acceso de red y destino autorizado | No prevista | Posible desde servicio | Native TCP probe por definir | Mide conexión TCP, no RTT ICMP |
| `network.http.probe` | Previsto con stack HTTP | Primera ola planificada | Acceso de red, TLS y destino autorizado | No prevista | Posible desde servicio | Desktop HTTP probe por definir | DNS, proxy, TLS y servidor forman parte del método |
| `traffic.tcp.throughput` | Previsto con provider compatible | Primera ola planificada | Ejecución allowlisted, red y reserva | No prevista | Posible desde servicio mientras lease y política sigan vigentes | `traffic-provider-iperf3`; fallback nativo diferido | Destino y límites efectivos obligatorios; provider/version quedan en resultado |
| `traffic.udp.throughput` | Previsto con provider compatible | Primera ola planificada | Ejecución allowlisted, red y reserva | No prevista | Posible desde servicio mientras lease y política sigan vigentes | `traffic-provider-iperf3`; fallback nativo diferido | Bitrate, pérdida, datagrama y dirección deben quedar explícitos |
| `traffic.http.download` | Previsto con stack HTTP | Primera ola posterior al núcleo de tráfico | Acceso de red, TLS y reserva | No prevista | Posible desde servicio | Desktop HTTP traffic provider por definir | Cache, proxy, compresión y servidor afectan comparabilidad |
| `traffic.http.upload` | Previsto con stack HTTP | Primera ola posterior al núcleo de tráfico | Acceso de red, TLS y reserva | No prevista | Posible desde servicio | Desktop HTTP traffic provider por definir | Requiere límites efectivos de bytes, duración y bitrate |
| `traffic.latency_under_load` | Posible componiendo traffic generator y probe independiente | Planificada después de probes y tráfico base | Permisos de ambos providers y reserva | No prevista | Posible mientras ambos componentes y lease estén activos | Composite provider por definir | Coordinación temporal y fuente del probe son parte del método |
| `capture.ip` | Condicionado a driver/provider de captura compatible | Diferida respecto de la primera ola del agente | Instalación autorizada y privilegio de captura | Puede requerirse para instalar o aprobar driver | Posible con servicio y límites | Windows capture provider por definir | Tiempo, tamaño, interfaz y filtro obligatorios; sin descifrado |
| `capture.ieee80211.monitor` | No se promete en el endpoint Windows baseline | No planificada para endpoint común | No aplicable al baseline | No aplicable | No aplicable | Ninguno seleccionado | Hardware/driver especializado no se infiere de captura IP |
| `traffic.pcap.replay` | Deliberadamente no disponible para endpoint común | Excluida del agente Windows | No aplicable | No aplicable | No aplicable | Ninguno | Replay sólo en Capture Node Linux especializado y autorizado |
| `execution.background.continuous` | Previsto mediante Windows Service sujeto a políticas del host | Primera ola planificada | Instalación y cuenta de servicio autorizadas | Instalación/administración inicial | Servicio continuo, sin prometer inmunidad a reboot o policy | Windows Service host | Debe recuperar estado local y respetar shutdown/update |

## Linux

Cada descripción depende de distribución y versión, kernel, hardware, driver,
network manager, permisos, capabilities del proceso y APIs disponibles. Ubuntu
22.04+ es referencia, no garantía universal. Nada está implementado todavía.

| Capability | technical_support | implementation_status | permission_requirement | user_interaction | background_execution | provider | limitations |
|---|---|---|---|---|---|---|---|
| `wifi.connection.read` | Previsto con stack Wi-Fi compatible | Primera ola planificada | Acceso a NetworkManager, nl80211 u otra API seleccionada | No prevista normalmente | Consultas desde systemd | Linux Wi-Fi OS adapter por definir | Debe registrar backend y fuente utilizados |
| `wifi.scan` | Condicionado a adapter, driver y stack de gestión | Primera ola planificada | Puede requerir privilegios o policy de NetworkManager | No prevista normalmente | Posible, sujeto a throttling y coexistencia | Linux Wi-Fi OS adapter por definir | Scan puede interrumpir o alterar mediciones; no equivale a captura monitor |
| `wifi.rssi.read` | Condicionado a asociación y datos expuestos | Primera ola planificada | Acceso a API de link o driver | No prevista | Muestreo periódico si la API lo permite | Linux Wi-Fi OS adapter por definir | Unidad, suavizado y fuente deben preservarse |
| `network.icmp.ping` | Posible mediante socket o comando registrado | Primera ola planificada | Puede requerir capability del proceso o binario allowlisted | No prevista | Posible desde systemd | ICMP probe por definir | Firewall y namespace pueden impedirlo; fallback se declara distinto |
| `network.tcp.probe` | Previsto con sockets | Primera ola planificada | Acceso de red y destino autorizado | No prevista | Posible desde systemd | Native TCP probe por definir | No sustituye semánticamente ICMP |
| `network.http.probe` | Previsto con stack HTTP | Primera ola planificada | Acceso de red, certificados y destino autorizado | No prevista | Posible desde systemd | Desktop HTTP probe por definir | Proxy, DNS y TLS integran el método |
| `traffic.tcp.throughput` | Previsto con provider compatible | Primera ola planificada | Proceso allowlisted, red y reserva | No prevista | Posible desde systemd bajo lease | `traffic-provider-iperf3`; fallback nativo diferido | Límites efectivos y destino obligatorios |
| `traffic.udp.throughput` | Previsto con provider compatible | Primera ola planificada | Proceso allowlisted, red y reserva | No prevista | Posible desde systemd bajo lease | `traffic-provider-iperf3`; fallback nativo diferido | Bitrate y tamaño de datagrama sujetos a política/provider |
| `traffic.http.download` | Previsto con stack HTTP | Planificada después del núcleo | Acceso de red, TLS y reserva | No prevista | Posible desde systemd | Desktop HTTP traffic provider por definir | Cache/proxy/compresión afectan método |
| `traffic.http.upload` | Previsto con stack HTTP | Planificada después del núcleo | Acceso de red, TLS y reserva | No prevista | Posible desde systemd | Desktop HTTP traffic provider por definir | Límites de bytes, duración y bitrate obligatorios |
| `traffic.latency_under_load` | Posible componiendo providers independientes | Planificada después de tráfico base | Permisos combinados y reserva | No prevista | Posible bajo lease activo | Composite provider o Flent opcional | Flent sería provider opcional, no capability |
| `capture.ip` | Condicionado a kernel, interfaz y provider | Diferida; prevista para Linux autorizado | Privilegios mínimos de captura | No prevista tras aprovisionamiento | Posible desde systemd con límites | Linux IP capture provider por definir | Interfaz, filtro, tamaño y duración obligatorios |
| `capture.ieee80211.monitor` | Posible sólo con hardware/driver y modo monitor compatibles | Reservada principalmente al rol Capture Node | Privilegios y preparación autorizada de interfaz | Puede requerirse durante aprovisionamiento | Posible sólo en nodo especializado | Linux monitor capture provider por definir | Canal, radiotap, interferencia y sincronización condicionan resultados |
| `traffic.pcap.replay` | Deliberadamente no disponible al agente Linux común | Excluida del rol endpoint | No aplicable al endpoint | No aplicable | No aplicable | Ninguno en rol endpoint | Sólo Capture Node aislado y allowlisted |
| `execution.background.continuous` | Previsto mediante systemd | Primera ola planificada | Instalación y service account autorizadas | Administración inicial | Servicio continuo sujeto a reboot, policy y updates | systemd service host | Recuperación local e idempotencia obligatorias |

## Android

Cada descripción depende de versión/API level, fabricante, hardware, driver,
permisos runtime, restricciones de energía, Foreground Service y APIs
disponibles. Android 10/API 29 es el mínimo contractual. La implementación se
difiere aunque el contrato contemple la plataforma.

| Capability | technical_support | implementation_status | permission_requirement | user_interaction | background_execution | provider | limitations |
|---|---|---|---|---|---|---|---|
| `wifi.connection.read` | Posible bajo APIs y permisos de la versión | Implementación diferida | Permisos Wi-Fi/ubicación o equivalentes según API | Puede requerir concesión runtime | Lectura durante lifecycle permitido | Android Wi-Fi adapter por definir | Datos pueden estar redactados o no disponibles; registrar `reason` |
| `wifi.scan` | Posible pero restringido por API level, estado y throttling | Implementación diferida | Permisos runtime y servicios requeridos por la versión | Concesión runtime y posibles acciones del usuario | No garantiza scan inmediato en background | Android Wi-Fi scan adapter por definir | Scan throttling y políticas del fabricante forman parte de limitations |
| `wifi.rssi.read` | Posible para conexión actual cuando API y permisos exponen valor | Implementación diferida | Permisos según API level | Puede requerir concesión runtime | Muestreo sujeto a lifecycle y actualización del OS | Android Wi-Fi adapter por definir | No asumir frescura ni comparabilidad con captura 802.11 |
| `network.icmp.ping` | No se promete ICMP uniforme; puede depender del dispositivo y API | Implementación diferida | Puede requerir capacidades no disponibles a apps comunes | No prevista más allá de permisos | Sin garantía de continuidad | Android probe por investigar | TCP/HTTP serán fallback explícito, no equivalentes |
| `network.tcp.probe` | Posible con sockets permitidos | Implementación diferida | Internet/network state según diseño final | No prevista para una ejecución foreground | Acotado por lifecycle; Foreground Service para trabajo visible | Native Android TCP provider por definir | Doze, cambios de red y handover afectan resultados |
| `network.http.probe` | Posible con stack HTTP | Implementación diferida | Internet y políticas TLS | No prevista para ejecución foreground | WorkManager no garantiza inmediatez; foreground cuando corresponda | OkHttp/Retrofit adapter futuro | DNS, TLS, proxy/VPN y lifecycle integran el método |
| `traffic.tcp.throughput` | Posible mediante sockets nativos bajo límites móviles | Implementación diferida | Red y Foreground Service cuando aplique | Puede requerir iniciar o mantener ejecución visible | Sólo dentro de mecanismos permitidos | Native Android traffic provider por definir | iperf3 no es baseline móvil; reserva y límites obligatorios |
| `traffic.udp.throughput` | Posible mediante sockets nativos bajo límites móviles | Implementación diferida | Red y Foreground Service cuando aplique | Puede requerir ejecución visible | Sólo dentro de mecanismos permitidos | Native Android traffic provider por definir | Bitrate y datagramas sujetos a OS, red y política |
| `traffic.http.download` | Posible con stack HTTP | Implementación diferida | Internet, TLS y reserva | Puede requerir ejecución visible | Bounded work; no ejecución inmediata garantizada | OkHttp traffic provider por definir | Cache y restricciones de datos/energía se registran |
| `traffic.http.upload` | Posible con stack HTTP | Implementación diferida | Internet, TLS y reserva | Puede requerir ejecución visible | Bounded work; no ejecución inmediata garantizada | OkHttp traffic provider por definir | Bytes y duración efectivos obligatorios |
| `traffic.latency_under_load` | Posible si OS mantiene generator y probe simultáneos | Implementación diferida | Permisos combinados y foreground | Probablemente ejecución visible | Condicionada por Foreground Service y recursos | Composite Android provider por definir | Thermal throttling, batería y switching de red afectan método |
| `capture.ip` | Posible sólo en forma limitada mediante mecanismos permitidos como VPN local | Implementación diferida y no equivalente a captura raw | Consentimiento y APIs de VPN según versión | Consentimiento explícito y servicio visible | Sujeto a lifecycle de VPN/Foreground Service | Android VPN capture provider por evaluar | No promete link layer, tráfico de terceros ni monitor mode |
| `capture.ieee80211.monitor` | No disponible para app Android común | No planificada | No aplicable al baseline | No aplicable | No aplicable | Ninguno | No se eluden sandbox, permisos ni firmware |
| `traffic.pcap.replay` | No disponible para endpoint Android común | Excluida | No aplicable | No aplicable | No aplicable | Ninguno | Replay limitado a Capture Nodes Linux |
| `execution.background.continuous` | No se promete daemon continuo; sólo mecanismos permitidos | Implementación diferida | Permisos y tipos de Foreground Service según versión | Visibilidad persistente y posible intervención | Condicionada y terminable por OS/usuario | Foreground Service y WorkManager | No equivale a servicio desktop permanente |

## iOS

Cada descripción depende de versión de iOS, dispositivo, hardware, permisos,
entitlements, estado de la app y APIs públicas disponibles. iOS 16 es el
mínimo contractual. La implementación se difiere y el modelo es
foreground-first.

| Capability | technical_support | implementation_status | permission_requirement | user_interaction | background_execution | provider | limitations |
|---|---|---|---|---|---|---|---|
| `wifi.connection.read` | Posible sólo bajo condiciones y APIs públicas habilitadas | Implementación diferida | Permisos o entitlements aplicables según caso | Puede requerir autorización o contexto configurado | Sin polling continuo garantizado | iOS Wi-Fi adapter por evaluar | No prometer datos universales; usar `reason` si el OS no expone |
| `wifi.scan` | No existe scan genérico prometido para app común | No planificada | No aplicable al baseline | No aplicable | No aplicable | Ninguno | Suggestion/Specifier de otras plataformas no tienen paridad directa |
| `wifi.rssi.read` | No se promete RSSI universal | No planificada como lectura universal | No aplicable al baseline | No aplicable | No aplicable | Ninguno | Cualquier signal quality expuesta por API específica sería método distinto |
| `network.icmp.ping` | No se promete ICMP genérico y portable | Implementación diferida para fallback, no para ICMP garantizado | Depende de APIs públicas disponibles | No prevista más allá de foreground | Sin continuidad garantizada | Probe iOS por investigar | TCP/HTTP son alternativas explícitas, no medición equivalente |
| `network.tcp.probe` | Posible con Network.framework o sockets permitidos | Implementación diferida | Acceso de red y políticas de la app | App activa para ejecución inmediata | Background no garantiza inicio ni continuidad | Network.framework provider por definir | Cambios de path y lifecycle forman parte del resultado |
| `network.http.probe` | Posible con URLSession | Implementación diferida | Red, TLS y políticas ATS aplicables | App activa para timing inmediato | Background URLSession sirve casos acotados, no scheduling inmediato | URLSession provider por definir | DNS, TLS, cache y path integran el método |
| `traffic.tcp.throughput` | Posible con sockets nativos en condiciones permitidas | Implementación diferida | Red y políticas de la app | Se espera foreground para prueba controlada | No se promete continuidad arbitraria | Native iOS traffic provider por definir | iperf3 no es baseline; reserva y límites obligatorios |
| `traffic.udp.throughput` | Posible con APIs de red permitidas | Implementación diferida | Red y políticas de la app | Se espera foreground | No se promete continuidad arbitraria | Native iOS traffic provider por definir | Bitrate y datagrama sujetos a path, OS y política |
| `traffic.http.download` | Posible con URLSession | Implementación diferida | Red, TLS y reserva | Foreground para timing controlado | Background transfer es acotado y no inmediato | URLSession traffic provider por definir | Cache y decisiones del OS deben quedar registradas |
| `traffic.http.upload` | Posible con URLSession | Implementación diferida | Red, TLS y reserva | Foreground para timing controlado | Background upload sólo bajo mecanismos permitidos | URLSession traffic provider por definir | Límites efectivos y archivo temporal controlado |
| `traffic.latency_under_load` | Posible sólo si el lifecycle mantiene ambos flujos | Implementación diferida | Permisos de red y foreground | Interacción/foreground esperados | No se garantiza en background | Composite iOS provider por definir | Thermal state, path changes y suspensión afectan comparabilidad |
| `capture.ip` | No se promete captura genérica para app común | No planificada en baseline | Entitlements especiales no se asumen | No aplicable al baseline | No aplicable | Ninguno | Network Extension no se trata como permiso universal de captura |
| `capture.ieee80211.monitor` | No disponible para app iOS común | Excluida | No aplicable | No aplicable | No aplicable | Ninguno | No se promete monitor mode ni tramas de terceros |
| `traffic.pcap.replay` | No disponible para endpoint iOS común | Excluida | No aplicable | No aplicable | No aplicable | Ninguno | Replay limitado a Capture Nodes Linux |
| `execution.background.continuous` | No existe daemon permanente prometido | Excluida como continuidad permanente | Background modes/entitlements no se generalizan | Foreground requerido para ejecución inmediata | BackgroundTasks y URLSession no garantizan ejecución continua | SwiftUI lifecycle, BackgroundTasks y URLSession | APNs sólo avisa; el servidor debe aceptar expiración o demora |

## Capture Node

El rol se referencia sobre Ubuntu 22.04+ y depende además de kernel, hardware,
driver, firmware, permisos, aislamiento, interfaces y APIs disponibles. Es un
rol especializado; nada está implementado todavía.

| Capability | technical_support | implementation_status | permission_requirement | user_interaction | background_execution | provider | limitations |
|---|---|---|---|---|---|---|---|
| `wifi.connection.read` | Posible sólo si el nodo también usa una interfaz Wi-Fi asociada | Diferida y secundaria al rol de captura | Acceso a stack de red | No prevista tras aprovisionamiento | Posible desde systemd | Linux Wi-Fi adapter por definir | No confundir interfaz de management con radio monitor |
| `wifi.scan` | Posible con hardware/driver compatible, pero puede interferir captura | Diferida | Privilegios y policy de interfaz | Puede requerir preparación inicial | Programable con cautela | Linux scan adapter por definir | Debe coordinar canal y ventanas de captura |
| `wifi.rssi.read` | No representa RSSI del endpoint bajo prueba | No planificada como capability de endpoint | No aplicable | No aplicable | No aplicable | Ninguno para esta semántica | RSSI por trama pertenece a captura IEEE 802.11 y no es equivalente |
| `network.icmp.ping` | Posible con red y privilegios compatibles | Diferida | Capability de proceso o comando allowlisted | No prevista | Posible desde systemd | Linux ICMP provider por definir | Su rol de captura no otorga destinos arbitrarios |
| `network.tcp.probe` | Posible con sockets | Diferida | Red y destino autorizado | No prevista | Posible desde systemd | Native Linux TCP provider | Límites y allowlist obligatorios |
| `network.http.probe` | Posible con stack HTTP | Diferida | Red, TLS y destino autorizado | No prevista | Posible desde systemd | Linux HTTP provider por definir | Proxy/DNS/TLS forman parte del método |
| `traffic.tcp.throughput` | Posible sólo si el nodo recibe además rol de Traffic Node | No asumida por ser Capture Node | Reserva y autorización de rol adicional | No prevista | Posible bajo systemd y lease | `traffic-provider-iperf3` si se autoriza el rol | Separar recursos de captura y tráfico para evitar sesgo |
| `traffic.udp.throughput` | Posible sólo con rol de Traffic Node adicional | No asumida por ser Capture Node | Reserva y autorización de rol adicional | No prevista | Posible bajo systemd y lease | `traffic-provider-iperf3` si se autoriza el rol | Bitrate y concurrencia deben proteger captura/control |
| `traffic.http.download` | Posible con rol de tráfico adicional | Diferida | Reserva y rol autorizado | No prevista | Posible bajo límites | Linux HTTP provider por definir | No se deriva automáticamente del rol Capture Node |
| `traffic.http.upload` | Posible con rol de tráfico adicional | Diferida | Reserva y rol autorizado | No prevista | Posible bajo límites | Linux HTTP provider por definir | No se deriva automáticamente del rol Capture Node |
| `traffic.latency_under_load` | Posible con roles y recursos separados | Diferida | Reservas y providers autorizados | No prevista | Posible si no degrada captura | Composite provider por definir | La captura simultánea puede alterar CPU, disco y red |
| `capture.ip` | Propósito previsto del rol con interfaz compatible | Planificada en fase de Capture Node | Privilegios mínimos y aislamiento | Aprovisionamiento inicial autorizado | Ejecución bounded desde systemd | Linux IP capture provider por definir | Tiempo, tamaño, interfaz y filtro obligatorios |
| `capture.ieee80211.monitor` | Posible con radio, driver y firmware compatibles | Planificada para nodo especializado | Privilegios y control autorizado de interfaz/canal | Aprovisionamiento y posible selección de canal | Ejecución bounded desde systemd | Linux monitor capture provider por definir | No garantiza observar todas las tramas; radiotap y sincronización importan |
| `traffic.pcap.replay` | Posible sólo en entorno aislado y autorizado | Diferida a fase especializada | Permiso específico, allowlist y red de laboratorio | Puede requerir habilitación operativa explícita | Bounded; nunca continuo sin límite | Tcpreplay provider futuro, no habilitado por defecto | Destino, interfaz, duración, tasa, captura y rollback operativos obligatorios |
| `execution.background.continuous` | Previsto mediante systemd | Planificada con el agente Linux | Instalación y service account autorizadas | Administración inicial | Servicio continuo sujeto a host/policy | systemd service host | Las operaciones individuales siguen teniendo duración y límites |

## Provider iperf3

iperf3 se documenta exclusivamente como provider/plugin:

```yaml
provider_id: traffic-provider-iperf3
implements:
  - traffic.tcp.throughput
  - traffic.udp.throughput
```

El fragmento es conceptual. Manifiesto, schemas, invocación, argumentos,
versiones soportadas y cadena de firma se definirán posteriormente.

## Métricas y comparabilidad

Toda salida medida usa conceptualmente:

- `value`
- `unit`
- `source`
- `availability`
- `confidence`
- `reason`

`reason` es el único campo conceptual de explicación. `value: null` no
significa cero. Las comparaciones deben registrar si método, fuente, provider, versión, dirección,
protocolo y contexto son equivalentes, aproximados o no comparables, sin
congelar todavía un enum contractual.

## Límites

`limitations` describe dimensiones posibles, no valores universales. Un
manifest puede declarar restricciones observadas y una política puede imponer
límites menores. Para tráfico, un valor solicitado `null` hereda política y la
reserva debe materializar números efectivos antes de ejecutar.

## Actualización de la matriz

La matriz debe revisarse cuando cambie un mínimo de OS, se seleccione un
provider, se pruebe hardware/driver, cambien permisos o entitlements, o una API
sea deprecada. Una prueba real puede reducir una afirmación provisional, pero
no se debe aumentar soporte basándose sólo en documentación del proveedor.
