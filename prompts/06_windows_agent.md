# Prompt 06 - Agente Windows

## Objetivo

Implementar el adaptador Windows y empaquetarlo como servicio instalable para Windows 10/11.

## Prerrequisitos

- Prompt 05 completo.
- Equipo/VM Windows para integración.

## Alcance

- Inventario.
- Telemetría Wi-Fi.
- Control permitido.
- Servicio.
- Packaging preliminar.
- Captura IP opcional.

## Requisitos de implementación

- Priorizar Windows Native Wi-Fi API y APIs estructuradas; PowerShell como soporte; netsh solo fallback localizado.
- Detectar interfaces, driver, SSID/BSSID, señal, canal/frecuencia cuando estén disponibles, TX/RX rate, IP, gateway, DNS y counters.
- Registrar source/availability por campo.
- Implementar Windows Service con recuperación.
- Usar DPAPI/Windows Credential Manager para secretos.
- Integrar iperf3 y dumpcap mediante ProcessRunner allowlisted, no desde lógica de dominio.
- Mapear interfaces Npcap de forma robusta.
- Agregar instalador firmable y uninstall limpio.
- No asumir privilegios administrativos permanentes.

## Tests obligatorios

- Fixtures de salida localizada.
- Windows Service lifecycle.
- Permisos insuficientes.
- Adaptadores múltiples.
- Sleep/resume y cambio de red.
- Integración real en Windows 10/11.

## Documentación obligatoria

- Matriz de campos Windows.
- Instalación, upgrade y rollback.
- Requisitos de Npcap/iperf3.
- Troubleshooting de idioma y permisos.

## Criterios de aceptación

- Se enrola como servicio.
- Publica datos honestos.
- Ejecuta pruebas permitidas.
- Sobrevive a reboot.
- Desinstala sin dejar secretos.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
