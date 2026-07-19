# Fase 07: agente Linux y Capture Node

Esta fase extiende el Desktop Agent Core; no crea un segundo agente. Reutiliza
identidad, credenciales, SQLite, manifests, heartbeat, idempotencia, leases
locales/simulados, outboxes y el lifecycle de procesos existente.

Componentes:

- adapter Linux con NetworkManager por D-Bus como fuente primaria;
- fallbacks de sólo lectura `ip` JSON, `iw`, `ethtool` y archivos `sysfs`;
- Secret Service no interactivo o archivos AES-GCM 0700/0600;
- unidades systemd distintas para endpoint y Capture Node;
- DEB inicial sin descargas durante instalación;
- Capture Node con policy, snapshot durable, rollback verificado, dumpcap y
  fingerprint/binding idempotente, recovery marker previo a la reserva y
  staging local de artifacts en root independiente;
- doctor Linux estrictamente read-only y clasificación lexical cerrada de
  journals activos, pending, manual recovery y retired;
- Flent condicional y tcpreplay limitado a validación/simulación.

Referencias:

- [Arquitectura y fuentes](architecture.md)
- [Distribuciones, instalación y packaging](installation-and-distributions.md)
- [Seguridad y permisos](security-and-permissions.md)
- [Runbook del Capture Node](capture-node-runbook.md)
- [Recuperación de interfaz](interface-recovery-runbook.md)
- [Pruebas y limitaciones](testing-and-limitations.md)
- [Troubleshooting](troubleshooting.md)

No se afirma validación sobre NIC, driver o hardware real: las rutas
privilegiadas se cubren con simulación y quedan opt-in en un laboratorio
autorizado.
