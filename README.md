# Ethernet LAN Report

A Python script that generates a self-contained HTML connectivity report for a Windows ethernet adapter — modelled after the built-in `netsh wlan show wlanreport` but for wired LAN connections.

---

## Usage

```bash
# Default: last 3 days, "Ethernet" adapter, output to current directory
python Generate-LanReport.py

# Custom options
python Generate-LanReport.py --days 7 --adapter "Ethernet 2" --out "C:\Reports"
```

The report is saved as `lan-report-YYYY-MM-DD.html` and opens automatically in the default browser.

---

## Command-line options

| Option | Default | Description |
|---|---|---|
| `--days N` | `3` | Days of Windows Event Log history to pull |
| `--adapter NAME` | `Ethernet` | Ethernet adapter alias to focus on |
| `--out PATH` | Current directory | Folder where the HTML report is saved |

---

## What the report contains

### Session graph
An interactive canvas timeline (similar to the WLAN report) showing network events plotted across three rows:

| Row | Events shown |
|---|---|
| Ethernet | Connect (C), Disconnect (D) |
| NCSI | Internet (I), Local (L), No Network (N) |
| Power | Sleep (S), Wake (W) |

Click any event dot to jump to its entry in the session list. Hover to see a summary.

### Report sections

| Section | Content |
|---|---|
| **General System Info** | Computer name, manufacturer, model, BIOS version/date, OS build, machine GUID |
| **User Info** | Username, domain, DNS domain, MDM join status |
| **Network Adapters** | All adapters — description, GUID, status, MAC, link speed, driver version/date |
| **Script Output** | Raw output of diagnostic commands (see below) |
| **Summary** | Session success/failure counts with bar chart; session duration histogram |
| **LAN Sessions** | Per-session breakdown with start/end time, status, and individual event rows |

### Diagnostic commands captured

- `ipconfig /all`
- `netsh interface show interface`
- `netsh interface ip show config` (IPv4 + IPv6)
- `Get-NetAdapter` / `Get-NetAdapterStatistics`
- `arp -a`
- `route print`
- `netsh interface ip show dns`

### Event log sources queried

| Log | Purpose |
|---|---|
| `Microsoft-Windows-NetworkProfile/Operational` | Network connect/disconnect events |
| `Microsoft-Windows-NCSI/Operational` | Internet vs. local vs. no-connectivity probes |
| `Microsoft-Windows-Wired-AutoConfig/Operational` | 802.1X wired authentication |
| `Microsoft-Windows-Dhcp-Client/Admin` | DHCP lease events |
| `System` (Event IDs 42, 107) | Sleep and wake power events |

---

## Requirements

- Windows (uses PowerShell and Windows Event Log APIs internally)
- Python 3.7+
- No third-party packages — standard library only

---

## Files

| File | Purpose |
|---|---|
| `Generate-LanReport.py` | Main script — collects data and renders the HTML report |
| `lan-report-2026-05-19.html` | Sample generated LAN report |
| `wlan-report-2026-05-19.html` | Sample Windows built-in WLAN report (reference) |
| `Windows has a built-in Wi-Fi report...pdf` | Reference article about the Windows WLAN report feature |
