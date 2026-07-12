# Limitaciones de Fase 05

No se implementan collectors Wi-Fi, probes de red, iperf3, comandos productivos,
Windows Service, systemd, updater funcional, packaging final del servicio ni el
servidor definitivo de tasks.

El Capability Manifest contiene las 15 capabilities pero declara collectors,
probes, tráfico y background service como planned, not implemented, excluded o
unavailable según plataforma. No reutiliza el fixture desktop como afirmación
de soporte real.

TaskRunner y scheduler se ejercitan con modelos locales y
`SimulatedAgentTransport`. Los stubs internos de Fase 04 no son consumidos por
`HttpAgentTransport` ni se presentan como API estable. Outboxes reales no se
eliminarán contra un servidor hasta que exista confirmación durable definida
por contratos públicos.
