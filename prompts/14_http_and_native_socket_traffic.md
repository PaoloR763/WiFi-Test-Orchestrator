# Prompt 14 - Tráfico HTTP y sockets nativos multiplataforma

## Objetivo

Implementar proveedores de tráfico realista y portables para Windows, Linux, Android e iOS.

## Prerrequisitos

- Prompt 12 completo.
- Endpoints de prueba controlados.

## Alcance

- HTTP download/upload.
- Native TCP stream.
- UDP stream opcional.
- Mobile-friendly execution.
- Server endpoints.

## Requisitos de implementación

- HTTP provider con archivos/payloads controlados, no cacheables, checksum y límites.
- Medir DNS/connect/TLS/TTFB/total cuando la API lo exponga.
- Soportar upload/download, fixed bytes y fixed duration.
- Sockets nativos con framing, sequence numbers y acknowledgements para medir bytes/intervalos sin mezclar con iperf3.
- Server de eco/throughput detrás de autenticación y reservas.
- Android: OkHttp + sockets; iOS: URLSession + Network.framework.
- Desktop: mismo contrato como fallback.
- Controlar network binding en mobile cuando sea permitido y reportarlo.
- Registrar thermal/battery/network path.
- Manejar app suspendida como interrupción explícita.
- No declarar equivalencia automática con iperf3.

## Tests obligatorios

- Cache prevention.
- TLS.
- Partial upload.
- Cambio de red.
- App background.
- Checksum.
- IPv6.
- Servidor lento.
- Comparación cross-platform.

## Documentación obligatoria

- Protocolo del servidor nativo.
- Métricas disponibles por plataforma.
- Perfiles mobile.
- Limitaciones de comparación.

## Criterios de aceptación

- Android/iOS generan tráfico sin binario externo.
- Resultados incluyen método.
- El servidor impone cuotas.
- No hay falsa equivalencia con iperf3.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
