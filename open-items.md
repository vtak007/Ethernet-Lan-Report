# Ethernet LAN Report — Open Items

## Status

| #   | Item                                            | Status                   |
| --- | ----------------------------------------------- | ------------------------ |
| 1   | Stale doc references to removed PDF / Readme.md | Waiting on your approval |
| 2   | Windows-only                                    | Accepted                 |
| 3   | Event IDs/log sources tuned to STRIX007         | Accepted                 |

## VERIFY

None.

## WATCH

None.

## DECIDE

1. `README.md` (Files table) and `CLAUDE.md` (Key Files) still list the `Windows has a built-in Wi-Fi report...pdf` removed in cca50e6, and `CLAUDE.md` still says `Readme.md`. Approve a fix to both.

## BLOCKED

None.

## ACCEPTED

2. Windows only: it relies on PowerShell cmdlets, `netsh`, and the Windows Event Log.
3. Event sources and IDs are tuned to STRIX007 (DHCP Admin log because Operational is disabled; NCSI 4042; NetworkProfile 4001–4004/10000/10001). Other machines may log different IDs, so some timeline events could be missing there.

## Git Actions Outstanding

None.
