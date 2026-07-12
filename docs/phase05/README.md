# Fase 05: núcleo del agente desktop

Fase 05 incorpora un runtime Python compartido para Windows y Linux bajo
`agents/desktop/`. El core no importa APIs de sistema operativo, no ejecuta
comandos productivos y no consume los stubs internos de tasks de Fase 04.

La comunicación productiva se limita a las APIs públicas de enrolamiento,
rotación de credenciales, Capability Manifest y heartbeat desktop. Scheduling,
TaskRunner y outboxes se prueban con `SimulatedAgentTransport` y modelos locales
hasta que Fase 10 publique los contratos autoritativos de tasks.

- [Arquitectura](architecture.md)
- [Configuración](configuration.md)
- [SQLite y migraciones](sqlite-storage.md)
- [Plugins desktop](desktop-plugins.md)
- [Seguridad de procesos y secretos](process-and-secret-security.md)
- [Doctor y troubleshooting](doctor-and-troubleshooting.md)
- [Recuperación y rollback](recovery-and-rollback.md)
- [Limitaciones](limitations.md)
