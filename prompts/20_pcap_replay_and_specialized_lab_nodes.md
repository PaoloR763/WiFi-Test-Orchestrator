# Prompt 20 - Replay de PCAP y nodos especializados de laboratorio

## Objetivo

Diseñar la incorporación segura de Tcpreplay y otras herramientas de alto privilegio sin exponerlas a agentes comunes.

## Prerrequisitos

- Prompt 19 completo.
- Capture/Lab Node Linux definido.

## Alcance

- LabNode role.
- ReplayProfile.
- Tcpreplay provider.
- Network isolation.
- Safety approvals.
- Results/artifacts.

## Requisitos de implementación

- Crear rol `LabNode` separado con enrolamiento y políticas específicas.
- Tcpreplay solo en Linux y redes de laboratorio identificadas.
- ReplayProfile versionado con PCAP hash, interface, rate, loops, rewrite policy y destination scope.
- Requerir aprobación/permiso adicional y preflight de interfaz/red.
- Usar namespaces, VLAN/VRF o aislamiento disponible.
- Prohibir PCAP no autorizado, destinos públicos y replay indefinido.
- Validar tamaño, tipo y hash.
- Capturar counters de envío, drops y timestamps.
- Soportar dry-run y simulador.
- Documentar que replay de paquetes no equivale a tráfico de aplicación con estado.
- Preparar hooks futuros para TRex u otros generadores, sin implementarlos.

## Tests obligatorios

- Policy denial.
- Wrong interface.
- Public route detection.
- Timeout.
- PCAP corrupto.
- Rate limit.
- Cleanup.
- Audit.

## Documentación obligatoria

- Runbook de LabNode.
- Threat model específico.
- Guía de ReplayProfile.
- Procedimiento de aprobación.

## Criterios de aceptación

- Un endpoint común no puede ejecutar replay.
- El LabNode requiere política explícita.
- No queda tráfico tras cancelación.
- La auditoría es completa.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
