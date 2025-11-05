import subprocess
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # <-- patch import

# ---------------------------
# Utility functions
# ---------------------------
def safe_subprocess(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, shell=False)
        return out.decode(errors="ignore")
    except:
        return ""

def pid_to_name(pid):
    """Return process name for a PID, or 'Unknown' / 'Terminated'"""
    if not pid or pid == "0":
        return None
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL
        )
        line = out.decode(errors="ignore").strip()
        if not line or "No tasks" in line:
            return "Terminated"
        parts = [p.strip(' \"') for p in line.split(',')]
        return parts[0] if parts else "Unknown"
    except:
        return "Unknown"

# ---------------------------
# NetstatDetector class
# ---------------------------
class NetstatDetector(BaseDetector):
    name = "netstat"

    def __init__(self, interval=5.0):
        super().__init__(interval)
        self.last_connections = set()
        self.active_pids = set()
        self.pid_cache = {}  # pid -> last known name
        
        # ------------------ logger per-detector ------------------
        self.logger = DetectorLogger(self.name)
        #self.logger.info("NetstatDetector initialized")        

    # -----------------------
    # Internal parsing
    # -----------------------
    def parse_netstat_output(self, output):
        parsed = set()
        pids = set()
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
                proto = parts[0]
                local = parts[1]
                remote = parts[2]
                state = parts[3] if proto == "TCP" else ""
                pid = parts[-1]
                parsed.add((proto, local, remote, state, pid))
                pids.add(pid)
        return parsed, pids

    # -----------------------
    # Event generation
    # -----------------------
    def generate_events(self, new_conns, current_pids):
        events = []

        # New connections
        for proto, local, remote, state, pid in new_conns:
            pname = self.pid_cache.get(pid) or pid_to_name(pid)
            self.pid_cache[pid] = pname
            event = {
                "type": "netstat",
                "event": "NEW_CONN",
                "proto": proto,
                "local": local,
                "remote": remote,
                "state": state,
                "pid": pid,
                "process": pname,
                "ts": now_ts()
            }
            evt = {
                "detector": self.name,
                "event": event,
                "_monitor_ts": now_ts()
            }            
            self.logger.info(evt)
            events.append(event) 

        # PID lifecycle
        new_pids = current_pids - self.active_pids
        terminated_pids = self.active_pids - current_pids
        reused_pids = current_pids & self.active_pids

        # New PID
        for pid in new_pids:
            pname = pid_to_name(pid)
            self.pid_cache[pid] = pname
            event = {"type": "netstat", "event": "NEW_PID", "pid": pid, "process": pname, "ts": now_ts()}
            evt = {
                "detector": self.name,
                "event": event,
                "_monitor_ts": now_ts()
            }            
            self.logger.info(evt)
            events.append(event) 

        # Terminated PID
        for pid in terminated_pids:
            pname = self.pid_cache.get(pid, "Unknown")
            event = {"type": "netstat", "event": "TERMINATED", "pid": pid, "process": pname, "ts": now_ts()}
            evt = {
                "detector": self.name,
                "event": event,
                "_monitor_ts": now_ts()
            }            
            self.logger.info(evt)
            events.append(event) 

        # Reused PID (name changed)
        for pid in reused_pids:
            old_name = self.pid_cache.get(pid)
            new_name = pid_to_name(pid)
            if old_name != new_name:
                event = {
                    "type": "netstat",
                    "event": "REUSED",
                    "pid": pid,
                    "old_process": old_name,
                    "new_process": new_name,
                    "ts": now_ts()
                }
                evt = {
                    "detector": self.name,
                    "event": event,
                    "_monitor_ts": now_ts()
                }            
                self.logger.info(evt)
                events.append(event) 
                self.pid_cache[pid] = new_name

        # Update state
        self.active_pids = current_pids
        return events

    # -----------------------
    # Polling
    # -----------------------
    def poll(self):
        output = safe_subprocess(["netstat", "-ano"])
        parsed, current_pids = self.parse_netstat_output(output)
        new_conns = parsed - self.last_connections
        self.last_connections = parsed
        return self.generate_events(new_conns, current_pids)
