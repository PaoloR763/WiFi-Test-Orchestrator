# Prompt 09 - Agente iOS/iPadOS nativo

## Objetivo

Crear una aplicación Swift foreground-first para pruebas de red, sin depender de capacidades no expuestas por iOS.

## Prerrequisitos

- Prompt 04 completo.
- Mac con Xcode y dispositivo real para integración.

## Alcance

- Enrolamiento.
- Keychain.
- Capabilities.
- Cola local.
- Network.framework.
- URLSession.
- BackgroundTasks como optimización.
- UI de campañas.

## Requisitos de implementación

- Swift/SwiftUI.
- URLSession para HTTP y uploads/downloads.
- Network.framework para TCP/UDP/path monitoring.
- Keychain para credenciales.
- Persistencia local con Core Data/SQLite o solución aprobada.
- BGTaskScheduler solo para sincronización elegible; no garantizar horario.
- APNs como hint, no orden garantizada.
- Capability `foreground_required` para pruebas largas.
- Access WiFi Information solo si entitlement y condiciones aplican.
- No prometer RSSI, scan genérico, monitor mode ni captura general.
- Preparar integración MDM/TestFlight sin asumir App Store público.
- Registrar thermal state y battery state solo cuando sea permitido.

## Tests obligatorios

- XCTest.
- Network.framework mocks.
- Foreground/background.
- App terminada por usuario.
- Sin entitlement.
- Cambio de path.
- Device real.

## Documentación obligatoria

- Matriz iOS/iPadOS.
- Entitlements.
- Distribución.
- Limitaciones y semántica de background.

## Criterios de aceptación

- La app ejecuta pruebas foreground.
- No reporta datos inexistentes.
- Resultados se sincronizan al reabrir.
- Tareas incompatibles quedan BLOCKED/SKIPPED.

## Forma de entrega

Antes de modificar código, inspeccioná `AGENTS.md`, ADRs, contratos, migraciones, ejemplos y tests relacionados. Presentá un plan breve. Implementá código completo, ejecutá las validaciones, corregí fallas y entregá un handoff con archivos, decisiones, comandos, resultados, riesgos y rollback.
