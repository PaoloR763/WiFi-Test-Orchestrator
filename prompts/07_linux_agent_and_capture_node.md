# Prompt 07 - Agente Linux y Capture Node

## Objetivo

Implementar el agente Linux y un rol especializado de Capture Node para captura 802.11 y herramientas avanzadas.

## Prerrequisitos

- Prompt 05 completo.
- Host Linux/VM para integración.

## Alcance

- NetworkManager/DBus.
- iw/ip/ethtool fallbacks.
- systemd.
- Packaging.
- Capture Node.
- Flent/Tcpreplay opcionales.

## Requisitos de implementación

- Usar APIs estructuradas cuando existan y encapsular comandos.
- Detectar interfaces, wiphy, driver, SSID/BSSID, frecuencia/canal, ancho, RSSI, rates, IP y counters.
- Servicio systemd con hardening.
- Secretos mediante permisos estrictos o keyring.
- Paquetes DEB primero; diseño para RPM.
- Rol Capture Node separado con NICs compatibles, channel lock, radiotap, timestamp y artifact upload.
- Flent solo si dependencias están instaladas y capability declarada.
- Tcpreplay solo en Capture/Lab Node, destino allowlisted y namespace/red aislada.
- Nunca habilitar monitor mode automáticamente en un endpoint de usuario.

## Tests obligatorios

- NetworkManager presente/ausente.
- systemd lifecycle.
- Cambio de interfaz.
- Permisos dumpcap.
- Capture Node simulation.
- Safety tests de tcpreplay.

## Documentación obligatoria

- Matriz de distros.
- Instalación DEB.
- Configuración de capabilities especiales.
- Runbook de Capture Node y seguridad.

## Criterios de aceptación

- Agente Linux funcional.
- Capture Node es un rol explícito.
- Herramientas avanzadas no están disponibles sin política.
- Rollback restaura interfaz.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
