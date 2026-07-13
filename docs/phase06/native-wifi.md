# Native Wi-Fi

El wrapper Windows-only carga `wlanapi.dll` desde System32 con `use_last_error=True`. Declara
firmas ctypes, libera buffers con `WlanFreeMemory` exactamente una vez y cierra cada handle.
Counts, tamaños, offsets e IE data tienen límites antes de ser recorridos.

SSID se conserva como bytes base64 y display UTF-8 sólo cuando es válido e imprimible. GUID y
BSSID se normalizan. Scan es no dirigido, sin IE arbitrario, con lock por GUID, cooldown,
notification complete/fail y timeout. Una red oculta mantiene display ausente.

`ERROR_ACCESS_DENIED` de privacidad no habilita otro provider para recuperar SSID, BSSID,
asociación o scan. Session 0 no muestra UI; `doctor` remite al ajuste de Location de Windows.

Referencias primarias: [wlanapi.h](https://learn.microsoft.com/windows/win32/api/wlanapi/),
[WlanScan](https://learn.microsoft.com/windows/win32/api/wlanapi/nf-wlanapi-wlanscan),
[WLAN_BSS_ENTRY](https://learn.microsoft.com/windows/win32/api/wlanapi/ns-wlanapi-wlan_bss_entry)
y [cambios de privacidad/location](https://learn.microsoft.com/windows/win32/nativewifi/wi-fi-access-location-changes).
