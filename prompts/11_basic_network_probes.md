# Prompt 11 - Pruebas básicas de red y conectividad

## Objetivo

Implementar plugins portables de latencia, DNS, HTTP y conectividad por etapas.

## Prerrequisitos

- Prompt 10 completo.
- Plugin API disponible.

## Alcance

- Latency probe.
- DNS.
- HTTP/HTTPS.
- Connectivity pipeline.
- Stability session básica.

## Requisitos de implementación

- LatencyProbe abstracto con ICMP, TCP connect, HTTP request y UDP echo cuando corresponda.
- No comparar métodos distintos sin etiquetarlos.
- DNS usando resolver del SO y opción de servidor dirigido donde la plataforma lo permita.
- HTTP con DNS, connect, TLS, TTFB, total, status y bytes según API disponible.
- Connectivity pipeline: interface/path, IP, gateway cuando sea observable, DNS y application endpoint.
- Stability session con muestras periódicas, desconexiones, BSSID/path changes y gaps.
- Thresholds versionados y snapshot.
- Destinos allowlisted.
- Timeouts y límites.

## Tests obligatorios

- Éxito/falla por etapa.
- IPv4/IPv6.
- DNS timeout.
- TLS error.
- Redirects.
- Captive portal.
- Cambio de path.
- Comparabilidad.

## Documentación obligatoria

- Referencia de cada método.
- Ejemplos de thresholds.
- Limitaciones por plataforma.
- Troubleshooting de resultados.

## Criterios de aceptación

- El resultado identifica la etapa exacta.
- Conserva método y proveedor.
- No usa cero para datos faltantes.
- Los plugins son extensibles.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
