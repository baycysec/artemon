# eventlog.py (patched)
import subprocess, json, time, os
from monitor import BaseDetector, now_ts
from datetime import datetime, timezone
import re  # penting untuk parse_ps_datetime
from logger_util import DetectorLogger  # <--- patch ini

def safe_subprocess(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except:
        return ""

def parse_ps_datetime(ps_date_str):
    """
    Convert PowerShell /Date(1760338385522)/ -> ISO8601 string
    """
    if not ps_date_str:
        return None
    try:
        m = re.search(r'/Date\((\d+)\)/', ps_date_str)
        if m:
            ts_ms = int(m.group(1))
            dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            return dt.isoformat()
    except Exception:
        pass
    return ps_date_str  # fallback ke string original

class SimpleEventLogDetector(BaseDetector):
    r"""
    Event log detector with configurable logs and optional EventID filters.

    logs_config: dict mapping LogName -> list_of_ids_or_None
      e.g. {
        "Security": [4624, 4625, 4688],
        "System": None,
        "Application": None,
        "Microsoft-Windows-PowerShell/Operational": [4104],
        "Microsoft-Windows-TaskScheduler/Operational": [106,140]
      }

    interval: poll interval in seconds
    max_events_per_log: upper bound per Get-WinEvent -MaxEvents
    """    
    name = "eventlog"

    def __init__(self, logs_config=None, interval: float = 5.0, max_events_per_log: int = 50, output_callback=None):
        super().__init__(interval)
        # default minimal sensible set if not provided
        if logs_config is None:
            logs_config = {
                "Security": [4624, 4625, 4688, 4689, 4672, 1102],
                "System": None,
                "Application": None,
                "Microsoft-Windows-TaskScheduler/Operational": [106, 140],
                "Microsoft-Windows-PowerShell/Operational": [4104]
            }
        self.logger = DetectorLogger(self.name)  # <--- patch: buat logger per-detector
        self.logs_config = logs_config
        self.max_events_per_log = int(max_events_per_log)
        self.realtime = True  # pseudo-realtime flag
        self._seen_event_keys = set()  # deduplication set

    def _build_ps_query_for_log(self, logname, ids):
        """
        Build a small PowerShell snippet for a single log.
        Uses FilterHashtable when ids provided; else get -LogName and -MaxEvents.
        Returns a string snippet.
        """
        log_esc = logname.replace("'", "''")
        if ids:
            ids_list = ",".join(str(int(i)) for i in ids)
            # Gunakan Where-Object supaya bisa filter Id *atau* ProviderName
            return (
                f"Get-WinEvent -LogName '{log_esc}' -MaxEvents {self.max_events_per_log} | "
                f"Where-Object {{$_.Id -in @({ids_list})}} | "
                "Select-Object TimeCreated,Id,LevelDisplayName,Message,ProviderName,LogName"
            )
        else:
            return (
                f"Get-WinEvent -LogName '{log_esc}' -MaxEvents {self.max_events_per_log} | "
                "Select-Object TimeCreated,Id,LevelDisplayName,Message,ProviderName,LogName"
            )

    def poll(self):
        events = []
        for logname, ids in self.logs_config.items():
            ps_command = self._build_ps_query_for_log(logname, ids) + " | ConvertTo-Json -Compress"
            ps = ["powershell", "-NoProfile", "-Command", ps_command]
            out = safe_subprocess(ps)
            if not out.strip():
                continue
            try:
                data = json.loads(out)
                if not isinstance(data, list):
                    data = [data]
            except Exception:
                data = []
            for ev in data:
                # unik key untuk dedup: log + Id + TimeCreated + Provider
                key = f"{ev.get('LogName')}_{ev.get('Id')}_{ev.get('TimeCreated')}_{ev.get('ProviderName')}"
                if key in self._seen_event_keys:
                    continue  # skip duplicate
                self._seen_event_keys.add(key)

                # convert TimeCreated
                timecreated = parse_ps_datetime(ev.get("TimeCreated"))

                # -----------------------------
                # PATCH: Write trigger file for schtask.py
                # -----------------------------
                try:
                    logname = ev.get("LogName") or ""
                    ev_id = ev.get("Id")
                    message = ev.get("Message") or ""

                    if (
                        "Microsoft-Windows-TaskScheduler/Operational" in logname
                        and ev_id in (106, 140, 141, 110, 111)
                    ):
                        taskname_match = re.search(r'task(?: scheduler)?\s+"(\\[^"]+)"', message, re.IGNORECASE)
                        if taskname_match:
                            taskname = taskname_match.group(1)
                            os.makedirs("logs/_event_signals", exist_ok=True)
                            trigger_path = os.path.join("logs", "_event_signals", "schtask_trigger.txt")
                            with open(trigger_path, "a", encoding="utf-8") as f:
                                f.write(f"{now_ts()} | {ev_id} | {taskname}\n")
                            print(f"[DEBUG] Writing trigger for task={taskname}, id={ev_id}")
                except Exception as e:
                    print(f"[!] Failed writing schtask trigger: {e}")

                # -----------------------------
                # Original event structure
                # -----------------------------
                event = {
                    "type": "eventlog",
                    "log": ev.get("LogName") or logname,
                    "id": ev.get("Id"),
                    "level": ev.get("LevelDisplayName"),
                    "provider": ev.get("ProviderName"),
                    "message": ev.get("Message"),
                    "timecreated": timecreated,
                    "ts": now_ts()
                }           
                evt = {
                    "detector": self.name,
                    "event": event,
                    "_monitor_ts": now_ts()
                }            
                self.logger.info(evt)
                events.append(event) 
        return events    
    