# Prompt 13 - Proveedor iperf3 y pool de servidores de prueba

## Objetivo

Implementar iperf3 como proveedor principal de throughput para Windows/Linux y administrar servidores de prueba controlados.

## Prerrequisitos

- Prompt 12 completo.
- iperf3 instalado o empaquetado de forma verificable.

## Alcance

- Cliente iperf3.
- Servidor/nodo iperf3.
- TCP/UDP.
- Reverse/bidir.
- JSON/streaming.
- Reservations.
- Health.

## Requisitos de implementación

- Ejecutar iperf3 mediante ProcessRunner allowlisted.
- Detectar versión y capacidades.
- Soportar TCP y UDP, uplink, reverse, bidirectional cuando la versión lo permita, streams paralelos, duration y bitrate.
- Usar JSON o json-stream; conservar salida cruda.
- Parsear intervals, end summary, retransmissions, jitter y loss según protocolo.
- Kill process tree y cleanup de puertos.
- Pool de servidores con tokens/reservas, max bitrate, max tests y server-bitrate-limit cuando esté disponible.
- No usar servidores públicos por defecto.
- Verificar hash/firma de binarios distribuidos y licencia.
- Capturar CPU y counters opcionales sin confundirlos con throughput.
- Fallback a provider alternativo debe ser explícito y registrado.

## Tests obligatorios

- Versiones soportadas.
- JSON parcial/corrupto.
- Server busy.
- UDP loss.
- Cancelación.
- Process hang.
- Port collision.
- Bidir/reverse.
- Integration Windows/Linux.

## Documentación obligatoria

- Instalación de iperf3.
- Operación del pool.
- Capacidades por versión.
- Troubleshooting y códigos de error.

## Criterios de aceptación

- TCP/UDP funcionan contra nodo controlado.
- Intervals llegan en tiempo real.
- No quedan procesos/puertos huérfanos.
- Límites del pool se respetan.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
