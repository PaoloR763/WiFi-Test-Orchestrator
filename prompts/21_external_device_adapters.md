# Prompt 21 - Adaptadores de AP, gateways, ONTs y controladores

## Objetivo

Crear un framework de integraciones externas para correlacionar estado de infraestructura y aplicar configuraciones controladas.

## Prerrequisitos

- Dominio y contratos estables.

## Alcance

- Adapter SDK.
- Read operations.
- Optional write operations.
- Secrets.
- Polling/events.
- Correlation.

## Requisitos de implementación

- Interfaces get_device_info, get_radios, get_clients, get_channel, get_width, get_utilization, get_noise, get_events y get_client_metrics.
- Adaptadores iniciales mock HTTP y SNMP simulado.
- Credenciales en secret store.
- Timeout/retry/circuit breaker.
- Mapping de MAC/agent/device con confianza.
- Write actions separadas, RBAC fuerte, snapshot before/after, validate y rollback.
- No ejecutar SSH genérico como consola remota.
- Preparar TR-181/USP, REST, SNMP y controller APIs.
- Registrar source, timestamp y freshness.
- Rate limits por sistema externo.

## Tests obligatorios

- Adapter unavailable.
- Stale data.
- Credential failure.
- Mapping ambiguity.
- Rollback.
- Circuit breaker.
- Contract tests.

## Documentación obligatoria

- SDK de adaptadores.
- Guía de credenciales.
- Ejemplo mock.
- Matriz de datos por proveedor.

## Criterios de aceptación

- Datos externos se distinguen de datos del agente.
- Write requiere permisos y rollback.
- Un nuevo adaptador no modifica el núcleo.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
