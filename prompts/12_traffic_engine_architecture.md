# Prompt 12 - Arquitectura del motor de tráfico y perfiles versionados

## Objetivo

Diseñar e implementar el contrato central de generación de tráfico sin acoplar el dominio a iperf3, HTTP o una plataforma.

## Prerrequisitos

- Prompts 04, 10 y 11 completos.

## Alcance

- TrafficGenerator API.
- TrafficProfile.
- Server capability/reservation.
- Normalized results.
- Policy engine.
- Provider registry.

## Requisitos de implementación

- Definir `TrafficGenerator.prepare/start/progress/stop/collect/cleanup` y semántica de cancelación.
- Definir protocolos TCP, UDP, HTTP y futuros QUIC/WebRTC sin implementarlos todos.
- Direcciones uplink, downlink, bidirectional y alternating.
- Parámetros: duration, bytes, streams, pacing, target bitrate, packet size, DSCP, IPv4/IPv6, warmup/cooldown.
- TrafficProfile versionado y reusable.
- TrafficServer pool con capabilities, capacity, health, reservations y affinity.
- Policies de destino, puertos, duración, bitrate, concurrencia y horario.
- Normalized interval metrics con timestamps monotónicos y wall clock.
- Declarar provider/version/platform/method.
- Registrar raw result como artifact y resumen normalizado.
- Diseñar capability negotiation y fallback explícito, nunca silencioso.
- Soportar dry-run/preflight.

## Tests obligatorios

- Schema/contract tests.
- Provider incompatible.
- Fallback explícito.
- Cancelación.
- Límites violados.
- Reserva concurrente.
- Intervalos fuera de orden.
- Golden fixtures.

## Documentación obligatoria

- SDK TrafficGenerator.
- Schema TrafficProfile.
- Guía para agregar proveedor.
- Catálogo de perfiles recomendados.
- Políticas de seguridad.

## Criterios de aceptación

- El dominio puede usar varios proveedores.
- Un perfil es reproducible e inmutable por versión.
- Los resultados son comparables solo cuando corresponde.
- Los límites bloquean abuso.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
