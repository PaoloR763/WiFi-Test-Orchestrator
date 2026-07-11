# Prompt 05 - Núcleo compartido de agentes desktop

## Objetivo

Implementar el runtime común para Windows y Linux sin acoplarlo a comandos o APIs de un sistema operativo.

## Prerrequisitos

- Prompt 04 completo.
- Contratos publicados.

## Alcance

- Transporte HTTPS.
- Cola SQLite.
- Task runner.
- Plugin registry.
- Adaptadores de plataforma.
- Configuración y diagnóstico.

## Requisitos de implementación

- Crear interfaces PlatformAdapter, WifiCollector, NetworkController, ProcessRunner, SecretStore y ServiceManager.
- Persistir tareas, resultados y uploads pendientes en SQLite.
- Garantizar exactly-once effect mediante idempotencia aunque la entrega sea at-least-once.
- Backoff con jitter.
- Allowlist de plugins y parámetros.
- Timeout, cancelación y cleanup.
- CLI: enroll, run, status, doctor, capabilities.
- Logs estructurados con redacción de secretos.
- No importar módulos Windows desde Linux ni viceversa.
- Proveer simuladores para CI.

## Tests obligatorios

- Reinicio durante tarea.
- Servidor offline.
- Resultado duplicado.
- Cancelación.
- Corrupción parcial de cola.
- Plugin no autorizado.
- Property tests de estados.

## Documentación obligatoria

- Arquitectura del agente.
- Formato de configuración.
- Guía de desarrollo de plugins desktop.
- Troubleshooting doctor.

## Criterios de aceptación

- El núcleo pasa tests en Windows y Linux.
- No duplica efectos.
- Recupera cola después de reinicio.
- No ejecuta comandos arbitrarios.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
