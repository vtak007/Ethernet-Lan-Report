# Ethernet LAN Report — Open Items

## Status

| #   | Item                                            | Status                   |
| --- | ----------------------------------------------- | ------------------------ |
| 1   | Windows-only                                    | Accepted                 |
| 2   | Event IDs/log sources tuned to STRIX007         | Accepted                 |

## VERIFY

None.

## WATCH

None.

## DECIDE

None.

## BLOCKED

None.

## ACCEPTED

1. Windows only: it relies on PowerShell cmdlets, `netsh`, and the Windows Event Log.
2. Event sources and IDs are tuned to STRIX007 (DHCP Admin log because Operational is disabled; NCSI 4042; NetworkProfile 4001–4004/10000/10001). Other machines may log different IDs, so some timeline events could be missing there.

## Git Actions Outstanding

None.
