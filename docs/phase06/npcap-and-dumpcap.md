# Npcap y dumpcap

Fase 06 sólo detecta Npcap, registry/options, estado del servicio, AdminOnly, Dot11Support,
versiones y presencia de dumpcap. Sólo se allowlistan `--version` y `-D -M`.

El mapeo usa GUID WLAN/NetAdapter y `NPF_{GUID}`; loopback queda separado. Coincidencia cero o
múltiple es unavailable. AdminOnly se reporta como permiso requerido.

No existe captura real, `-I`, monitor mode, inyección, replay, descifrado ni suposición de que
non-promiscuous limite toda visibilidad. `capture.ip` queda planned. Monitor 802.11 queda excluded
en Windows y technical support no se infiere por la opción genérica Dot11Support.

Referencias primarias: [Npcap Users' Guide](https://npcap.com/guide/npcap-users-guide.html),
[Npcap development guide](https://npcap.com/guide/npcap-devguide.html) y
[dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html).
