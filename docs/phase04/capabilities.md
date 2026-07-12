# Capability Manifest 1.0.0

El catálogo `1.0.0` exige exactamente estas 15 capabilities:

1. `wifi.connection.read`
2. `wifi.scan`
3. `wifi.rssi.read`
4. `network.icmp.ping`
5. `network.tcp.probe`
6. `network.http.probe`
7. `traffic.tcp.throughput`
8. `traffic.udp.throughput`
9. `traffic.http.download`
10. `traffic.http.upload`
11. `traffic.latency_under_load`
12. `capture.ip`
13. `capture.ieee80211.monitor`
14. `traffic.pcap.replay`
15. `execution.background.continuous`

Cada entrada declara exactamente `technical_support`,
`implementation_status`, `permission_requirement`, `user_interaction`,
`background_execution`, `provider` y `limitations`. No existe `support` ni
`availability_reason`; `reason` es la única explicación. Ausente, unknown,
not_implemented, denied/restricted y not_applicable permanecen distintos.

Provider es cerrado y admite como máximo ocho implementaciones. `iperf3` puede
aparecer como provider, nunca como capability. Limitations diferencia
unknown/not_applicable de valores numéricos; ausente o `null` jamás significa
cero.

Los vocabularios pertenecen al capability catalog y son cerrados. Agregar un
valor que un consumidor antiguo deba comprender requiere versión nueva del
catálogo y negociación explícita. Durante coexistencia el servidor conserva
fixtures y reglas por versión; un catálogo desconocido se rechaza.
