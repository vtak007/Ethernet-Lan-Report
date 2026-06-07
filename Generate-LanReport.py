#!/usr/bin/env python3
"""
Generate-LanReport.py
Ethernet LAN connectivity report generator for Windows.
Produces an HTML report similar to the built-in 'netsh wlan show wlanreport'.

Usage:
    python Generate-LanReport.py
    python Generate-LanReport.py --days 7 --adapter "Ethernet 2"
    python Generate-LanReport.py --out "C:\\Reports"
"""

import subprocess, json, datetime, os, sys, html as htmllib, re, argparse
from pathlib import Path

# ── Default settings ──────────────────────────────────────────────────────────
DEFAULT_DAYS    = 3          # How many days of event log history to pull
DEFAULT_ADAPTER = "Ethernet" # Adapter alias to highlight; set '' to show all
GRAPH_DAYS      = 2          # Canvas timeline width (days); mirrors wlan-report

# ── Low-level helpers ─────────────────────────────────────────────────────────
def run_ps(cmd, timeout=90):
    """Run a PowerShell command; return stdout (empty string on any error)."""
    try:
        r = subprocess.run(
            ['powershell', '-NonInteractive', '-NoProfile',
             '-ExecutionPolicy', 'Bypass', '-Command', cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace')
        return r.stdout.strip()
    except Exception:
        return ''

def run_cmd(cmd, timeout=30):
    """Run a shell command via cmd.exe; return stdout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, encoding='utf-8',
                           errors='replace', shell=True)
        return r.stdout
    except Exception:
        return ''

_ISO_RE = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?')

def parse_dt(s):
    """Parse an ISO-8601 string -> UTC-aware datetime (or None)."""
    if not s:
        return None
    m = _ISO_RE.search(str(s))
    if not m:
        return None
    base, frac, tz = m.group(1), m.group(2) or '', m.group(3) or ''
    if frac and len(frac) > 7:
        frac = frac[:7]
    tz = '+00:00' if tz in ('', 'Z') else tz
    try:
        dt = datetime.datetime.fromisoformat(base + frac + tz)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None

def dt_ms(dt):
    return int(dt.timestamp() * 1000) if dt else 0

def dt_iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S') if dt else ''

# ── Data collection ───────────────────────────────────────────────────────────
def get_sysinfo():
    ps = r"""
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os   = Get-CimInstance Win32_OperatingSystem
$guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -EA SilentlyContinue).MachineGuid
[ordered]@{
  ComputerName  = $env:COMPUTERNAME
  Manufacturer  = $cs.Manufacturer
  Model         = $cs.Model
  BiosDate      = if($bios.ReleaseDate){$bios.ReleaseDate.ToString('M/d/yyyy')}else{'Unknown'}
  BiosVersion   = $bios.SMBIOSBIOSVersion
  OSBuild       = $os.BuildNumber
  OSVersion     = $os.Version
  MachineGuid   = "{$guid}"
  Username      = $env:USERNAME
  UserDomain    = $env:USERDOMAIN
  UserDNSDomain = if($env:USERDNSDOMAIN){$env:USERDNSDOMAIN}else{'Unknown'}
  MDMJoined     = [bool](Get-Item 'HKLM:\SOFTWARE\Microsoft\Enrollments\*' -EA SilentlyContinue)
} | ConvertTo-Json"""
    try:
        return json.loads(run_ps(ps))
    except Exception:
        return {'ComputerName': os.environ.get('COMPUTERNAME', 'Unknown')}

def get_adapters():
    """Return list of adapter info dicts (all physical + virtual adapters)."""
    ps = r"""
Get-NetAdapter | Select-Object Name,InterfaceDescription,MacAddress,Status,
    LinkSpeed,DriverDate,DriverVersionString,InterfaceGuid,ifIndex,MediaType |
ConvertTo-Json -Depth 2"""
    try:
        d = json.loads(run_ps(ps))
        return d if isinstance(d, list) else [d]
    except Exception:
        return []

def get_win_events(log_name, max_events=500, days_back=3, ids=None):
    """
    Return a list of raw event dicts from a Windows Event Log.
    Each dict has: TimeCreated, Id, Level, Message, ProviderName
    """
    id_filter = ''
    if ids:
        id_list = ','.join(str(i) for i in ids)
        id_filter = f' -and (@({id_list}) -contains $_.Id)'
    ps = f"""
$cutoff = (Get-Date).AddDays(-{days_back})
try {{
    $evs = Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} -EA Stop |
        Where-Object {{$_.TimeCreated -ge $cutoff{id_filter}}} |
        ForEach-Object {{
            [ordered]@{{
                TimeCreated  = $_.TimeCreated.ToUniversalTime().ToString('o')
                Id           = [int]$_.Id
                Level        = $_.LevelDisplayName
                Message      = $_.Message
                ProviderName = $_.ProviderName
            }}
        }}
    if ($null -eq $evs) {{'[]'}} else {{$evs | ConvertTo-Json -Depth 2}}
}} catch {{'[]'}}"""
    try:
        d = json.loads(run_ps(ps))
        if d is None:
            return []
        return d if isinstance(d, list) else [d]
    except Exception:
        return []

def get_command_output(cmd_label, cmd):
    """Run a command and return (label, output_string)."""
    if cmd.startswith('ps:'):
        out = run_ps(cmd[3:])
    else:
        out = run_cmd(cmd)
    return cmd_label, out

# ── Event classification ──────────────────────────────────────────────────────
def classify(ev, eth_guid=''):
    """
    Map a raw event dict to (type_str, error_code, css_classes).
    Returns None to exclude the event from the session graph snapshots.
    type_str is one of: Connect Disconnect Internet Local None Sleep Wake
    """
    eid      = int(ev.get('Id', 0))
    provider = (ev.get('ProviderName') or '').lower()
    msg_raw  = (ev.get('Message') or '')
    msg      = msg_raw.lower()
    level    = (ev.get('Level') or '').lower()

    # ── Network Profile ──────────────────────────────────────────────────────
    # Filter out events for virtual adapters when we know the real adapter GUID
    if 'networkprofile' in provider:
        guid_match = not eth_guid or eth_guid.lower() in msg.lower()
        if eid == 10000:
            # "Network Connected" — check if it mentions our interface
            # Events without a GUID in message are general; include them
            return 'Connect',    '0', 'eth connect'
        if eid == 10001:
            return 'Disconnect', '0', 'eth disconnect'
        if eid == 10002:
            return 'Connect',    '0', 'eth connect'
        # 4001 = Entering Identifying state; 4002 = Identified; 4003 = Unidentified
        if eid == 4001 and guid_match:
            return 'Connect',    '0', 'eth'
        if eid == 4002 and guid_match:
            return 'Connect',    '0', 'eth connect'
        if eid == 4003 and guid_match:
            return 'Connect',    '0', 'eth'
        if eid == 4004:
            # "Network State Change Fired" — include as informational
            return 'Connect',    '0', 'eth'
        return None  # skip other NP events (20002 etc.)

    # ── NCSI connectivity probes ──────────────────────────────────────────────
    # EventID 4042 = "Capability change on {guid} (... Capability: Internet ...)"
    # EventID 4001 in NCSI log = state change
    if 'ncsi' in provider:
        if 'internet' in msg:
            return 'Internet', '0', 'ncsi internet'
        if 'local' in msg or 'limited' in msg:
            return 'Local', '0', 'ncsi local'
        if 'none' in msg or 'no connectivity' in msg:
            return 'None', '0', 'ncsi none'
        return 'Internet', '0', 'ncsi internet'   # default: treat unknown NCSI as status change

    # ── Kernel power (sleep / wake) ──────────────────────────────────────────
    if 'kernel-power' in provider or 'power-troubleshooter' in provider:
        if eid == 42:
            return 'Sleep', '0', 'ndis sleep'
        if eid in (1, 107):
            return 'Wake',  '0', 'ndis wake'
        # EventID 566 = session transition (lock/unlock) — skip
        return None

    # ── Wired 802.1X authentication ──────────────────────────────────────────
    if 'wired-autoconfig' in provider:
        err = str(eid) if 'error' in level else '0'
        css = 'error' if 'error' in level else 'wired'
        return 'Connect', err, css

    # ── DHCP lease events ──────────────────────────────────────────────────
    if 'dhcp' in provider:
        # Only include if related to our Ethernet adapter (MAC in message)
        return 'Connect', '0', 'dhcp'

    return None   # Not mapped → include in session list but not in graph

# ── Session grouping ──────────────────────────────────────────────────────────
def build_sessions(events):
    """
    Group enriched (classified) events into sessions.
    A session runs from a Connect event to the next Disconnect (or end of log).
    """
    sessions, current = [], []
    for ev in events:
        t = ev.get('_type')
        if t == 'Connect':
            if current:
                sessions.append(current)
            current = [ev]
        elif t == 'Disconnect':
            current.append(ev)
            sessions.append(current)
            current = []
        else:
            if current:
                current.append(ev)
    if current:
        sessions.append(current)
    return sessions

def session_stats(sessions):
    """Return (successes, failures, warnings, duration_histogram[7])."""
    ok = fail = warn = 0
    dur_counts = [0] * 7
    dur_edges  = [1, 5, 10, 30, 60, 360]     # minutes
    for s in sessions:
        has_error = any(ev.get('_error', '0') != '0' for ev in s)
        if has_error:
            fail += 1
        else:
            ok += 1
        times = [ev['_dt'] for ev in s if ev.get('_dt')]
        if len(times) >= 2:
            mins = (max(times) - min(times)).total_seconds() / 60
            idx = next((i for i, e in enumerate(dur_edges) if mins < e), 6)
            dur_counts[idx] += 1
    return ok, fail, warn, dur_counts

# ── HTML builders ─────────────────────────────────────────────────────────────
def h(s):
    """HTML-escape a string."""
    return htmllib.escape(str(s or ''), quote=True)

def render_css():
    return """\
<style type="text/css">
  body{margin:0;padding:0;background-color:#EFEFEF;font-family:"segoe ui light","segoe ui";letter-spacing:.03em}
  table{border-collapse:collapse}
  th{border:1px solid #222;text-align:center}
  tr{height:1.5em;border:1px solid #222}
  td{border:1px solid #222}
  #top-btn{position:fixed;padding:5px;border:2px solid #333;cursor:pointer}
  #top-btn p{margin:0}
  #report-wrapper{width:1000px;margin:0 auto}
  #session-graph-wrapper{background-color:#1F1F1F;outline:2px solid #AAA}
  #session-graph{cursor:pointer}
  #graph-event-info{float:left;width:500px;height:170px;color:#DDD;padding:0 30px 0 20px}
  #graph-event-info h4{margin:0 0 10px 0}
  #event-info{margin:0;height:135px;overflow:scroll}
  #sysinfo{margin:0 0 30px 0}
  #sysinfo p,#report-info p{margin:0;padding:0}
  #disconnect-status tr,#disconnect-status td{border:1px solid #222}
  #disconnect-status .status{width:300px;padding-top:0}
  #disconnect-reasons .reason{width:800px;padding-top:0}
  .count{width:75px;text-align:center}
  .graph-background{position:absolute;z-index:-1;height:1.5em;margin:-1px;background-color:rgb(171,168,244)}
  .graph-background.success{background-color:rgb(108,216,108)}
  .graph-background.failure{background-color:rgb(216,108,108)}
  .graph-background.warning{background-color:rgb(216,216,108)}
  #session-durations{border-left:1px solid #222;overflow:hidden}
  #duration-labels{text-align:center}
  #duration-graph{height:550px;border:none}
  #duration-graph td{width:80px;padding:0 2px;vertical-align:top;position:relative;border:none}
  .duration-bar{width:80px;position:absolute}
  .bar-label{width:80px;position:absolute;text-align:center;font-weight:bold}
  .bar-background{background-color:rgb(171,168,244);display:block;width:100%;height:100%;outline:1px solid #222}
  .session{background-color:#FFF;margin:0 0 20px 0;padding:10px;border:2px solid #666}
  .session p{margin:.2em}
  .session table{width:100%}
  .session .event-header{width:75px}
  .session .time-header{width:180px}
  .session .message-header{width:auto}
  .successful{background-color:#1BEB00}
  .warning{background-color:#EBEB00}
  .failed{background-color:#F00}
  .info{background-color:#E2E2E2}
  .message{width:700px;height:1.5em;overflow:hidden;white-space:pre;text-overflow:ellipsis}
  .message.show{height:auto;overflow:auto;white-space:normal}
  .message .expand-btn{cursor:pointer}
  .error{background-color:rgb(255,178,178);font-weight:bold}
  .ndis.sleep{background-color:#AF9AE4}
  .ndis.wake{background-color:#E49AEF}
  .eth{background-color:#FFF}
  .eth.connect{background-color:#9AE4A6}
  .eth.disconnect{background-color:#F5BE9C}
  .ncsi.internet{background-color:#9CCAF5}
  .ncsi.local{background-color:#F1F59C}
  .ncsi.none{background-color:#F59C9C}
  .wcm{background-color:#F0FFFF}
  .wired{background-color:#FFFFF0}
  .dhcp{background-color:#FFF8E7}
  .glow{font-weight:bold;outline:3px solid #000}
  #commands-output{margin:0 0 30px 0}
  .command-output{background-color:#000;color:#C0C0C0;padding:5px;outline:5px solid #BBB}
</style>"""

def render_sysinfo_section(sysinfo, adapters):
    lines = ['<div id="sysinfo">', '<h2>General System Info</h2>']
    lines.append(f'<p>ComputerName: <b>{h(sysinfo.get("ComputerName",""))}</b></p>')
    lines.append(f'<p>System Manufacturer: <b>{h(sysinfo.get("Manufacturer",""))}</b></p>')
    lines.append(f'<p>System Product Name: <b>{h(sysinfo.get("Model",""))}</b></p>')
    lines.append(f'<p>BIOS Date: <b>{h(sysinfo.get("BiosDate",""))}</b></p>')
    lines.append(f'<p>BIOS Version: <b>{h(sysinfo.get("BiosVersion",""))}</b></p>')
    lines.append(f'<p>OS Build: <b>{h(sysinfo.get("OSVersion",""))}</b></p>')
    lines.append(f'<p>Machine Id: <b>{h(sysinfo.get("MachineGuid",""))}</b></p>')
    lines.append(f'<p>MDM joined: <b>{h(sysinfo.get("MDMJoined", False))}</b></p>')
    lines.append('<h2>User Info</h2>')
    lines.append(f'<p>Username: <b>{h(sysinfo.get("Username",""))}</b></p>')
    lines.append(f'<p>User Domain: <b>{h(sysinfo.get("UserDomain",""))}</b></p>')
    lines.append(f'<p>User DNS Domain: <b>{h(sysinfo.get("UserDNSDomain","Unknown"))}</b></p>')
    lines.append('<h2>Network Adapters</h2>')
    for a in adapters:
        dd = a.get('DriverDate') or ''
        lines.append(f'<p>Device: <b>{h(a.get("InterfaceDescription",""))}</b></p>')
        lines.append(f'<p>Guid: <b>{h(a.get("InterfaceGuid",""))}</b></p>')
        lines.append(f'<p>Status: <b>{h(a.get("Status",""))}</b></p>')
        lines.append(f'<p>MAC Address: <b>{h(a.get("MacAddress",""))}</b></p>')
        lines.append(f'<p>Link Speed: <b>{h(a.get("LinkSpeed",""))}</b></p>')
        lines.append(f'<p>Driver Version: <b>{h(a.get("DriverVersionString",""))}</b></p>')
        lines.append(f'<p>Driver Date: <b>{h(dd)}</b></p><br>')
    lines.append('</div>')
    return '\n'.join(lines)

def render_command_outputs(cmd_outputs):
    lines = ['<div id="commands-output">', '<h2>Script Output</h2>']
    for label, output in cmd_outputs:
        lines.append(f'<h3>Output for <em>{h(label)}</em></h3>')
        lines.append(f'<textarea class="command-output" cols="91" rows="25" readonly spellcheck="false">')
        lines.append(h(output))
        lines.append('</textarea>')
    lines.append('</div>')
    return '\n'.join(lines)

def render_summary(ok, fail, warn, dur_counts, total_sessions):
    max_dur = max(dur_counts) if dur_counts else 1
    max_dur = max_dur or 1
    bar_max_px = 550

    def bar_width(count, total):
        if total == 0: return 0
        return int((count / total) * 300)

    total = ok + fail + warn or 1
    labels = ['0 - 1<br>minutes','1 - 5<br>minutes','5 - 10<br>minutes',
              '10 - 30<br>minutes','30 - 60<br>minutes','60 - 360<br>minutes','360+<br>minutes']

    dur_cells = []
    for i, cnt in enumerate(dur_counts):
        bar_h = int((cnt / max_dur) * bar_max_px) if max_dur else 0
        top   = bar_max_px - bar_h
        dur_cells.append(
            f'<td style="top:{top}px;">'
            f'<div class="duration-bar" style="height:{bar_h}px;">'
            f'<span class="bar-label" style="bottom:0px;">{cnt}</span>'
            f'<span class="bar-background">&nbsp;</span>'
            f'</div></td>'
        )

    return f"""
<div id="events-summary">
<h2>Summary</h2>
<h3>Session Success/Failures</h3>
<table id="disconnect-status">
<tr><th>Status</th><th>Count</th></tr>
<tr>
  <td class="status"><span class="graph-background success" style="width:{bar_width(ok,total)}px">&nbsp;</span>Successes</td>
  <td class="count">{ok}</td>
</tr>
<tr>
  <td><span class="graph-background failure" style="width:{bar_width(fail,total)}px">&nbsp;</span>Failures</td>
  <td class="count">{fail}</td>
</tr>
<tr>
  <td class="status"><span class="graph-background warning" style="width:{bar_width(warn,total)}px">&nbsp;</span>Warnings</td>
  <td class="count">{warn}</td>
</tr>
</table>
<h3>Session Durations</h3>
<table id="session-durations">
<tr id="duration-graph">{''.join(dur_cells)}</tr>
<tr id="duration-labels">{''.join(f'<td>{l}</td>' for l in labels)}</tr>
</table>
</div>"""

def render_session_row(ev):
    eid   = ev.get('Id', '')
    time  = dt_iso(ev.get('_dt'))
    msg   = (ev.get('Message') or '').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
    css   = ev.get('_css', '')
    err   = ev.get('_error', '0')
    row_css = css + (' error' if err != '0' else '')
    anchor = f'<a id="{ev.get("_seq","")}"></a>'
    return (
        f'<tr class="{h(row_css)}">'
        f'<td>{h(eid)}{anchor}</td>'
        f'<td>{h(time)}</td>'
        f'<td><div class="message"><span class="expand-btn">[+]</span>'
        f'<span class="message-body">{msg}</span></div></td>'
        f'</tr>'
    )

def render_sessions_section(sessions):
    lines = ['<h2>LAN Sessions</h2>', '<div id="session-list">']
    if not sessions:
        lines.append('<p>No sessions found in the selected time range.</p>')
    for s in sessions:
        if not s:
            continue
        times = [ev['_dt'] for ev in s if ev.get('_dt')]
        start_t = dt_iso(min(times)) if times else ''
        end_t   = dt_iso(max(times)) if times else ''
        types   = [ev.get('_type','') for ev in s]
        has_dis = 'Disconnect' in types
        status_css = 'failed' if any(ev.get('_error','0')!='0' for ev in s) else (
                     'successful' if has_dis else 'warning')
        lines.append('<div class="session">')
        lines.append(f'<p>Start: <b>{start_t}</b> &nbsp; End: <b>{end_t if has_dis else "Active"}</b>'
                     f' &nbsp; Status: <b class="{status_css}">'
                     f'{"Completed" if has_dis else "Active"}</b></p>')
        lines.append('<table>')
        lines.append('<tr class="info"><th class="event-header">EventId</th>'
                     '<th class="time-header">Time</th>'
                     '<th class="message-header">Message</th></tr>')
        for ev in s:
            lines.append(render_session_row(ev))
        lines.append('</table>')
        lines.append('</div>')
    lines.append('</div>')
    return '\n'.join(lines)

def render_graph_js(snapshots_js, graph_days):
    return f"""\
<script type="text/javascript">
var snapshots = {snapshots_js};

var lanReport = (function() {{
    var lanReport = {{}},
        pointRadius = 8,
        eventOffset = 50,
        ethYOffset   = 0,
        ncsiYOffset  = 100,
        ndisYOffset  = 200,
        eventRenderInfo,
        boundRenderInfo,
        ethBounds = [],
        connectivityBounds = [],
        powerBounds = [],
        bindToggleMessageBtns, toggleMessage,
        timeToXCoord, findNewestEvent, calculateEventCoordinates,
        findEthBounds, findConnectivityBounds, findPowerBounds,
        drawEvents, drawPoint, drawSessionBounds, drawBound,
        drawAxis, drawEventRegionLabels, drawLegend, drawLegendLabel,
        drawSessionGraph, eventClickHandler, eventMouseMoveHandler,
        calculateSessionDuration, getSnapshotAtXY, getSessionAtXY,
        convertSnapshotTimes, convertFileTimeToUnixTime,
        fixCommandOutputFormatting, checkForEmptyReport, bindTopBtn;

    eventRenderInfo = {{
        'Connect':    {{'label':'C','color':'#9AE4A6'}},
        'Disconnect': {{'label':'D','color':'#F5BE9C'}},
        'Sleep':      {{'label':'S','color':'#AF9AE4'}},
        'CS-Sleep':   {{'label':'S','color':'#AF9AE4'}},
        'Wake':       {{'label':'W','color':'#E49AEF'}},
        'CS-Wake':    {{'label':'W','color':'#E49AEF'}},
        'Internet':   {{'label':'I','color':'#9CCAF5'}},
        'Local':      {{'label':'L','color':'#F1F59C'}},
        'None':       {{'label':'N','color':'#F59C9C'}},
        'Error':      {{'label':'X','color':'#FF0000'}}
    }};

    boundRenderInfo = {{
        'Connected':        {{'fill':'rgba(0,210,0,0.3)','stroke':'rgba(0,210,0,0.8)','lineWidth':'3'}},
        'Power':            {{'fill':'rgba(0,0,0,0.95)','stroke':'rgba(20,20,20,1.0)','lineWidth':'1'}},
        'ConnectedStandby': {{'fill':'rgba(0,135,0,0.3)','stroke':'rgba(0,100,0,0.95)','lineWidth':'1'}}
    }};

    bindToggleMessageBtns = function() {{
        var els = document.getElementsByTagName('div'), btn, i;
        for (i = 0; i < els.length; i++) {{
            if (els[i].className === 'message') {{
                btn = els[i].firstChild;
                btn.addEventListener('click', toggleMessage(btn), false);
            }}
        }}
    }};

    toggleMessage = function(btn) {{
        return function() {{
            var msg = btn.parentNode;
            if (msg.className === 'message') {{
                msg.className = 'message show';
                btn.innerHTML = '[‒]';
            }} else {{
                msg.className = 'message';
                btn.innerHTML = '[+]';
            }}
        }};
    }};

    timeToXCoord = function(startTimeStr, snapshotTimeStr, width) {{
        var windowMS    = 1000 * 60 * 60 * 24 * {graph_days},
            startTime   = parseInt(startTimeStr, 10),
            snapshotTime= parseInt(snapshotTimeStr, 10),
            endTime     = startTime - windowMS,
            ratio       = (snapshotTime - startTime) / (endTime - startTime);
        return width - (ratio * width);
    }};

    findNewestEvent = function() {{
        var t = 0, i;
        for (i = 0; i < snapshots.length; i++) t = Math.max(t, snapshots[i].time);
        return t;
    }};

    calculateEventCoordinates = function(canvas) {{
        var width = canvas.width, xOff = 10, lastX = [], minDiff = 2 * pointRadius,
            startTime, xPos, yOff, i;
        if (!snapshots.length) return;
        lastX[ethYOffset] = lastX[ncsiYOffset] = lastX[ndisYOffset] = -1;
        startTime = findNewestEvent();
        for (i = 0; i < snapshots.length; i++) {{
            var t = snapshots[i].type;
            if (t==='Connect'||t==='Disconnect'||t==='Error') yOff = ethYOffset;
            else if (t==='Wake'||t==='CS-Wake'||t==='Sleep'||t==='CS-Sleep') yOff = ndisYOffset;
            else yOff = ncsiYOffset;
            xPos = timeToXCoord(startTime, snapshots[i].time, width) - xOff;
            if (lastX[yOff] >= 0 && (lastX[yOff] - xPos) < minDiff) {{
                xOff += minDiff - (lastX[yOff] - xPos);
                xPos = lastX[yOff] - minDiff;
            }}
            snapshots[i].x = xPos;
            snapshots[i].y = eventOffset + yOff;
            lastX[yOff] = xPos;
            if (xPos > width) {{ snapshots = snapshots.slice(0, i); break; }}
        }}
    }};

    drawEvents = function(canvas) {{
        var graph = canvas.getContext('2d'), snap, style, i;
        if (!snapshots.length) {{
            graph.font = '18px sans-serif';
            graph.fillStyle = '#EFEFEF';
            graph.textAlign = 'center';
            graph.fillText('No events in the last {graph_days} days', canvas.width/2, canvas.height/2);
            return;
        }}
        graph.strokeStyle = '#111'; graph.lineWidth = 1;
        for (i = 0; i < snapshots.length; i++) {{
            snap  = snapshots[i];
            style = (snap.error !== '0') ? eventRenderInfo['Error'] : eventRenderInfo[snap.type];
            if (!style) continue;
            graph.fillStyle = style.color;
            drawPoint(graph, snap.x, snap.y, style.label);
        }}
    }};

    drawPoint = function(graph, x, y, label) {{
        graph.font = '10px sans-serif'; graph.textAlign = 'center';
        graph.beginPath();
        graph.arc(x, y, pointRadius, 0, 2*Math.PI, false);
        graph.fill(); graph.stroke();
        graph.fillStyle = '#222';
        graph.fillText(label, x, y + pointRadius/2);
    }};

    findEthBounds = function() {{
        var connectEv = null, disconnectEv = null, isConn = false, cur, t, i;
        for (i = snapshots.length-1; i >= 0; i--) {{
            if (snapshots[i].type==='Disconnect') {{ isConn=true; break; }}
            else if (snapshots[i].type==='Connect') {{ isConn=false; break; }}
        }}
        if (isConn) {{
            for (i = snapshots.length-1; i >= 0; i--) {{
                t = snapshots[i].type;
                if (t==='Disconnect') {{
                    ethBounds.push({{connectEvent:snapshots[i],disconnectEvent:snapshots[i],
                        x:0,y:ethYOffset+eventOffset,width:snapshots[i].x,height:200}});
                    break;
                }}
            }}
        }}
        for (i = snapshots.length-1; i >= 0; i--) {{
            cur = snapshots[i]; t = cur.type;
            if (t==='Internet'||t==='Local'||t==='None') continue;
            if (t==='Connect') {{
                if (!connectEv) connectEv = cur;
                isConn = true;
            }} else if (t==='Disconnect'||t==='Sleep'||t==='CS-Sleep') {{
                disconnectEv = cur;
                if (t!=='Sleep'&&t!=='CS-Sleep') isConn = false;
                if (connectEv && disconnectEv) {{
                    ethBounds.push({{connectEvent:connectEv,disconnectEvent:disconnectEv,
                        x:connectEv.x,y:ethYOffset+eventOffset,
                        width:disconnectEv.x-connectEv.x,height:200}});
                }}
                if (!connectEv && !ethBounds.length) {{
                    ethBounds.push({{connectEvent:null,disconnectEvent:disconnectEv,
                        x:0,y:ethYOffset+eventOffset,width:disconnectEv.x,height:200}});
                }}
                connectEv = null; disconnectEv = null;
            }} else if (t==='Wake'||t==='CS-Wake') {{
                if (isConn && !connectEv) connectEv = cur;
            }}
        }}
        if (connectEv && !disconnectEv) {{
            ethBounds.push({{connectEvent:connectEv,disconnectEvent:null,
                x:connectEv.x,y:ethYOffset+eventOffset,width:1000,height:200}});
        }}
    }};

    drawSessionBounds = function(canvas) {{
        var graph = canvas.getContext('2d'), b, info, i;
        for (i = 0; i < ethBounds.length; i++) {{
            b = ethBounds[i]; info = boundRenderInfo['Connected'];
            graph.fillStyle   = info.fill;
            graph.strokeStyle = info.stroke;
            graph.lineWidth   = info.lineWidth;
            graph.fillRect(b.x, b.y, b.width, b.height);
            graph.strokeRect(b.x, b.y, b.width, b.height);
        }}
    }};

    drawAxis = function(canvas) {{
        var graph = canvas.getContext('2d'),
            w = canvas.width, h = canvas.height,
            now = findNewestEvent() || Date.now(),
            step = w / (24 * {graph_days}), x, lbl, d;
        graph.strokeStyle = '#666'; graph.lineWidth = 1;
        graph.fillStyle   = '#AAA'; graph.font = '10px sans-serif'; graph.textAlign = 'center';
        for (var hr = 0; hr <= 24 * {graph_days}; hr++) {{
            x   = w - hr * step;
            d   = new Date(now - hr * 3600000);
            lbl = d.getHours() + ':00';
            graph.beginPath(); graph.moveTo(x, 0); graph.lineTo(x, h); graph.stroke();
            if (hr % 2 === 0) graph.fillText(lbl, x, h - 5);
        }}
    }};

    drawEventRegionLabels = function(canvas) {{
        var graph = canvas.getContext('2d');
        graph.fillStyle = '#BBB'; graph.font = '12px sans-serif'; graph.textAlign = 'left';
        graph.fillText('Ethernet', 5, ethYOffset  + eventOffset - 20);
        graph.fillText('NCSI',     5, ncsiYOffset + eventOffset - 20);
        graph.fillText('Power',    5, ndisYOffset + eventOffset - 20);
        // Horizontal dividers
        graph.strokeStyle = '#555'; graph.lineWidth = 1;
        [[ethYOffset],[ncsiYOffset],[ndisYOffset]].forEach(function(row) {{
            graph.beginPath();
            graph.moveTo(0, row[0] + eventOffset - 25);
            graph.lineTo(canvas.width, row[0] + eventOffset - 25);
            graph.stroke();
        }});
    }};

    drawLegend = function(legendCanvas) {{
        var items = [
            {{'label':'C = Connect',    'color':'#9AE4A6'}},
            {{'label':'D = Disconnect', 'color':'#F5BE9C'}},
            {{'label':'I = Internet',   'color':'#9CCAF5'}},
            {{'label':'L = Local',      'color':'#F1F59C'}},
            {{'label':'N = No Network', 'color':'#F59C9C'}},
            {{'label':'S = Sleep',      'color':'#AF9AE4'}},
            {{'label':'W = Wake',       'color':'#E49AEF'}},
            {{'label':'X = Error',      'color':'#FF0000'}}
        ];
        var graph = legendCanvas.getContext('2d'), r = pointRadius, i, item;
        for (i = 0; i < items.length; i++) {{
            item = items[i];
            graph.fillStyle = item.color;
            graph.strokeStyle = '#111'; graph.lineWidth = 1;
            graph.beginPath();
            graph.arc(r + 5, i * 20 + r + 5, r, 0, 2*Math.PI, false);
            graph.fill(); graph.stroke();
            graph.fillStyle = '#DDD'; graph.font = '12px sans-serif'; graph.textAlign = 'left';
            graph.fillText(item.label, 2*r + 12, i * 20 + r + 10);
        }}
    }};

    drawSessionGraph = function() {{
        var canvas = document.getElementById('session-graph'),
            legend = document.getElementById('graph-legend');
        calculateEventCoordinates(canvas);
        drawAxis(canvas);
        drawEventRegionLabels(canvas);
        findEthBounds();
        drawSessionBounds(canvas);
        drawEvents(canvas);
        drawLegend(legend);
    }};

    eventClickHandler = function(e) {{
        var canvas = document.getElementById('session-graph'),
            rect = canvas.getBoundingClientRect(),
            mx = e.clientX - rect.left, my = e.clientY - rect.top,
            i, s;
        for (i = 0; i < snapshots.length; i++) {{
            s = snapshots[i];
            if (Math.abs(mx - s.x) <= pointRadius && Math.abs(my - s.y) <= pointRadius) {{
                var el = document.getElementById(String(s.seq));
                if (el) el.scrollIntoView();
                break;
            }}
        }}
    }};

    eventMouseMoveHandler = function(e) {{
        var canvas = document.getElementById('session-graph'),
            rect = canvas.getBoundingClientRect(),
            mx = e.clientX - rect.left, my = e.clientY - rect.top,
            infoEl = document.getElementById('event-info'),
            found = false, i, s, d;
        for (i = 0; i < snapshots.length; i++) {{
            s = snapshots[i];
            if (Math.abs(mx - s.x) <= pointRadius && Math.abs(my - s.y) <= pointRadius) {{
                d = new Date(parseInt(s.time));
                infoEl.innerHTML = '<b>Type:</b> ' + s.type + '<br>'
                    + '<b>Time:</b> ' + d.toLocaleString() + '<br>'
                    + '<b>Error:</b> ' + s.error + '<br>'
                    + '<b>Details:</b> ' + (s.details || '');
                found = true; break;
            }}
        }}
        if (!found) infoEl.innerHTML = 'Hover over an event to see details<br>Click to jump to the event in the session list';
    }};

    fixCommandOutputFormatting = function() {{
        var tas = document.querySelectorAll('textarea.command-output'), i;
        for (i = 0; i < tas.length; i++) tas[i].style.width = '100%';
    }};

    checkForEmptyReport = function() {{
        if (!snapshots.length) {{
            document.getElementById('event-info').innerHTML =
                'No network events found in the selected time range.';
        }}
    }};

    bindTopBtn = function() {{
        document.getElementById('top-btn').addEventListener('click', function() {{
            window.scrollTo(0, 0);
        }});
    }};

    lanReport.init = function() {{
        bindToggleMessageBtns();
        drawSessionGraph();
        document.getElementById('session-graph').addEventListener('mousemove', eventMouseMoveHandler);
        document.getElementById('session-graph').addEventListener('click', eventClickHandler);
        fixCommandOutputFormatting();
        checkForEmptyReport();
        bindTopBtn();
    }};

    return lanReport;
}}());

window.onload = function() {{ lanReport.init(); }};
</script>"""

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='Generate an Ethernet LAN connectivity report (similar to wlan-report).')
    parser.add_argument('--days',    type=int,   default=DEFAULT_DAYS,
                        help='Days of history to include (default: 3)')
    parser.add_argument('--adapter', type=str,   default=DEFAULT_ADAPTER,
                        help='Ethernet adapter alias to highlight (default: Ethernet)')
    parser.add_argument('--out',     type=str,   default=os.getcwd(),
                        help='Output directory (default: current dir)')
    args = parser.parse_args()

    today     = datetime.datetime.now().strftime('%Y-%m-%d')
    out_path  = Path(args.out) / f'lan-report-{today}.html'
    now_utc   = datetime.datetime.now(datetime.timezone.utc)
    days_back = args.days

    print(f'[*] LAN Report Generator  --  {today}')
    print(f'[*] Collecting data for the last {days_back} day(s)...')

    # ── System info ──
    print('[*] Gathering system info...')
    sysinfo  = get_sysinfo()
    adapters = get_adapters()

    # ── Command outputs ──
    print('[*] Running diagnostic commands...')
    cmd_outputs = []

    ipconfig = run_cmd('ipconfig /all')
    cmd_outputs.append(("ipconfig /all", ipconfig))

    netsh_if = run_cmd('netsh interface show interface')
    cmd_outputs.append(("netsh interface show interface", netsh_if))

    netsh_ip = run_ps(
        f'netsh interface ip show config "{args.adapter}" 2>&1; '
        f'Write-Host ""; netsh interface ipv6 show config "{args.adapter}" 2>&1')
    cmd_outputs.append((f'netsh interface ip show config "{args.adapter}"', netsh_ip))

    ps_adapter = run_ps(
        f'Get-NetAdapter -Name "{args.adapter}" -EA SilentlyContinue | Format-List *; '
        f'Write-Host "--- Statistics ---"; '
        f'Get-NetAdapterStatistics -Name "{args.adapter}" -EA SilentlyContinue | Format-List *')
    cmd_outputs.append((f'Get-NetAdapter / Get-NetAdapterStatistics "{args.adapter}"', ps_adapter))

    arp_table = run_cmd('arp -a')
    cmd_outputs.append(("arp -a", arp_table))

    route_table = run_cmd('route print')
    cmd_outputs.append(("route print", route_table))

    netsh_dns = run_cmd('netsh interface ip show dns')
    cmd_outputs.append(("netsh interface ip show dns", netsh_dns))

    # ── Event log queries ──
    print('[*] Querying Windows Event Logs...')

    # Discover the Ethernet adapter GUID — exact name match first, then fallback
    eth_guid = ''
    for a in adapters:
        name = (a.get('Name') or '')
        if name.lower() == args.adapter.lower():          # exact match (e.g. "Ethernet")
            eth_guid = str(a.get('InterfaceGuid') or '').strip('{}').lower()
            break
    if not eth_guid:
        for a in adapters:
            desc = (a.get('InterfaceDescription') or '').lower()
            mtype = (a.get('MediaType') or '').lower()
            name = (a.get('Name') or '').lower()
            # Physical 802.3 adapter that isn't Hyper-V or virtual
            if mtype == '802.3' and 'virtual' not in desc and 'hyper-v' not in desc \
               and 'hyper-v' not in name and 'vethernet' not in name.replace(' ',''):
                eth_guid = str(a.get('InterfaceGuid') or '').strip('{}').lower()
                if eth_guid:
                    break
    if eth_guid:
        print(f'[*] Ethernet adapter GUID: {{{eth_guid}}}')

    EVENT_SOURCES = [
        # (log_name, max_events, ids_filter_or_None)
        # All relevant NetworkProfile events (not just 10000/10001)
        ('Microsoft-Windows-NetworkProfile/Operational',   1000, None),
        ('Microsoft-Windows-NCSI/Operational',             500,  None),
        ('Microsoft-Windows-Wired-AutoConfig/Operational', 300,  None),
        # DHCP Admin log (Operational is disabled by default)
        ('Microsoft-Windows-Dhcp-Client/Admin',            200,  None),
        # Power events: sleep=42, wake=107; skip EventID 566 (session lock)
        ('System',                                         200,  [42, 107]),
    ]

    raw_events = []
    for log_name, max_ev, ids in EVENT_SOURCES:
        evs = get_win_events(log_name, max_events=max_ev, days_back=days_back, ids=ids)
        print(f'    {log_name}: {len(evs)} events')
        raw_events.extend(evs)

    # ── Enrich events ──
    enriched = []
    seq = 0
    for ev in raw_events:
        dt = parse_dt(ev.get('TimeCreated'))
        if dt is None:
            continue
        result = classify(ev, eth_guid=eth_guid)
        if result is None:
            ev_type, err, css = 'Info', '0', 'info'
        else:
            ev_type, err, css = result
        seq += 1
        ev['_dt']    = dt
        ev['_type']  = ev_type
        ev['_error'] = err
        ev['_css']   = css
        ev['_seq']   = seq
        enriched.append(ev)

    # Sort oldest → newest
    enriched.sort(key=lambda e: e['_dt'])

    # ── Build sessions ──
    sessions = build_sessions(enriched)
    ok, fail, warn, dur_counts = session_stats(sessions)
    print(f'[*] {len(sessions)} sessions found  ({ok} OK, {fail} failed, {warn} warnings)')

    # ── Build snapshots JSON for the canvas graph ──
    # Graph covers GRAPH_DAYS window; only include events of mapped types
    graph_cutoff = now_utc - datetime.timedelta(days=GRAPH_DAYS)
    snap_types   = {'Connect','Disconnect','Internet','Local','None','Sleep','Wake','CS-Sleep','CS-Wake'}
    snapshots = []
    for ev in reversed(enriched):   # newest first (matches WLAN report order)
        if ev['_dt'] < graph_cutoff:
            break
        if ev['_type'] not in snap_types:
            continue
        msg_short = (ev.get('Message') or '')[:120].replace('"', '\\"').replace('\n', ' ')
        snapshots.append({
            'time':    dt_ms(ev['_dt']),
            'type':    ev['_type'],
            'error':   ev['_error'],
            'seq':     ev['_seq'],
            'details': msg_short,
        })

    snapshots_js = json.dumps(snapshots, indent=4)

    # ── Render HTML ──
    print('[*] Generating HTML report...')

    sysinfo_html  = render_sysinfo_section(sysinfo, adapters)
    cmd_html      = render_command_outputs(cmd_outputs)
    summary_html  = render_summary(ok, fail, warn, dur_counts, len(sessions))
    sessions_html = render_sessions_section(sessions)
    graph_js      = render_graph_js(snapshots_js, GRAPH_DAYS)

    report_created = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    computer_name  = sysinfo.get('ComputerName', 'Unknown')

    html_doc = f"""<!DOCTYPE html>
<html>
<head>
<META http-equiv="Content-Type" content="text/html">
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>LAN Report - {h(computer_name)}</title>
{render_css()}
</head>
<body>
<div id="top-btn"><p>Top</p></div>
<div id="report-wrapper">
<h1>LAN Report</h1>
<div id="session-graph-wrapper">
  <canvas id="session-graph" width="1000" height="315"></canvas>
  <div id="graph-event-info">
    <h4>Summary</h4>
    <p id="event-info">Hover over an event to view a summary<br>Click an event to jump to it in the session list</p>
  </div>
  <canvas id="graph-legend" width="400" height="170"></canvas>
</div>

<div id="report-info">
<h2>Report Info</h2>
<p>Report created: <b>{h(report_created)}</b></p>
<p>Report duration: <b>{days_back} days</b></p>
<p>Adapter filter: <b>{h(args.adapter)}</b></p>
</div>

{sysinfo_html}
{cmd_html}
{summary_html}
{sessions_html}
</div>
{graph_js}
</body>
</html>"""

    out_path.write_text(html_doc, encoding='utf-8')
    print(f'[+] Report saved to: {out_path}')
    print(f'[+] Open in a browser: start "" "{out_path}"')

    # Auto-open in default browser
    try:
        os.startfile(str(out_path))
    except Exception:
        pass

if __name__ == '__main__':
    main()
