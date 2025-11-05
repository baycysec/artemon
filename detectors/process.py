# detectors/process.py
# Artemon ProcessDetector - Realtime Extended (Final Clean Patched)
# Mode: Realtime monitoring (poll-based via monitor.py)
# Includes: pid, ppid, parent_name, exe_path, username, hash_sha256, session_id

import psutil
import time
import hashlib
import ctypes
from datetime import datetime
from monitor import now_ts
from logger_util import DetectorLogger  # gunakan ini


def sha256_of_file(path):
    """Return SHA256 hash of file if readable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def get_session_id(pid):
    """Return Windows session ID for given process PID."""
    try:
        session_id = ctypes.c_ulong()
        res = ctypes.windll.kernel32.ProcessIdToSessionId(pid, ctypes.byref(session_id))
        if res == 0:
            return None
        return int(session_id.value)
    except Exception:
        return None

class ProcessDetector:
    """
    Realtime Process Detector for Artemon (Extended)
    Detects process creation, termination, and property changes (cmdline/ppid).
    Includes: pid, ppid, parent_name, exe_path, username, hash_sha256, session_id.
    Threading handled by monitor.py
    """

    name = "process"

    def __init__(self, interval: float = 2.0, hash_enable: bool = False):
        self.interval = interval
        self.hash_enable = hash_enable
        self.prev_snapshot = {}  # pid -> dict of process info
        self.output_callback = None
        self.initialized = False
       
        # ------------------ logger per-detector ------------------
        #self.logger = get_detector_logger(self.name)
        self.logger = DetectorLogger(self.name)
        #self.logger.info({"event": f"ProcessDetector initialized (hash_enable={self.hash_enable})"})


    # ---------------------- snapshot utils ----------------------
    def _get_snapshot(self):
        """Return dict of current processes and metadata."""
        snapshot = {}
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid', 'exe', 'username']):
            try:
                pid = proc.info['pid']
                name = proc.info.get('name') or ""
                cmdline = " ".join(proc.info.get('cmdline') or [])
                ppid = proc.info.get('ppid')
                exe_path = proc.info.get('exe') or ""
                username = proc.info.get('username') or ""
                session_id = get_session_id(pid)
                hashv = sha256_of_file(exe_path) if (self.hash_enable and exe_path) else None

                snapshot[pid] = {
                    "name": name,
                    "cmdline": cmdline,
                    "ppid": ppid,
                    "exe": exe_path,
                    "username": username,
                    "session_id": session_id,
                    "hash_sha256": hashv,
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return snapshot

    # ---------------------- polling loop ----------------------
    def poll(self):
        """Called periodically by monitor.py thread. Returns list of event dicts."""
        events = []
        current = self._get_snapshot()

        if not self.initialized:
            self.prev_snapshot = current
            self.initialized = True
            #self.logger.info("ProcessDetector initial snapshot taken (%d processes)" % len(current))
            event = {
                "event": f"Initial snapshot taken ({len(current)} processes)"
            }           
            evt = {
                "detector": self.name,
                "event": event,
                "_monitor_ts": now_ts()
            }            
            #self.logger.info(evt)
            #self.logger.info({"event": f"Initial snapshot taken ({len(current)} processes)"})
            return events

        prev = self.prev_snapshot

        # --- detect process creation ---
        created_pids = set(current.keys()) - set(prev.keys())
        for pid in created_pids:
            proc = current[pid]
            parent_name = self._resolve_parent_name(proc["ppid"], prev, current)
            #events.append(self._make_event("process_created", pid, proc, parent_name))
            #self.logger.info(f"Process created: pid={pid}, name={proc['name']}, exe={proc['exe']}")
            event = self._make_event("process_created", pid, proc, parent_name)
            #self.logger.info(event)
            # log ke file
            #self.logger.info({"event_type": "process_created", "pid": pid, **proc, "ts": now_ts()})            
            events.append(event)            

        # --- detect process termination ---
        terminated_pids = set(prev.keys()) - set(current.keys())
        for pid in terminated_pids:
            proc = prev[pid]
            parent_name = self._resolve_parent_name(proc["ppid"], prev, current)
            #events.append(self._make_event("process_terminated", pid, proc, parent_name))
            #self.logger.info(f"Process terminated: pid={pid}, name={proc['name']}, exe={proc['exe']}")            
            event = self._make_event("process_terminated", pid, proc, parent_name)
            #self.logger.info(event)
            #self.logger.info({"event_type": "process_terminated", "pid": pid, **proc, "ts": now_ts()})
            events.append(event)            

        # --- detect process change (cmdline or ppid) ---
        common_pids = set(prev.keys()) & set(current.keys())
        for pid in common_pids:
            old = prev[pid]
            new = current[pid]
            if old["cmdline"] != new["cmdline"] or old["ppid"] != new["ppid"]:
                parent_name = self._resolve_parent_name(new["ppid"], prev, current)
                event = {
                    "type": "process_changed",
                    "pid": pid,
                    "ppid": new["ppid"],
                    "parent_name": parent_name,
                    "process_name": new["name"],
                    "old_cmdline": old["cmdline"],
                    "new_cmdline": new["cmdline"],
                    "old_ppid": old["ppid"],
                    "new_ppid": new["ppid"],
                    "exe_path": new["exe"],
                    "username": new["username"],
                    "hash_sha256": new["hash_sha256"],
                    "session_id": new["session_id"],
                    "ts": now_ts(),
                }
                events = {
                    "detector": self.name,
                    "event": event,
                    "_monitor_ts": now_ts()
                }            
                events.append(event)
                self.logger.info(events)
                
        self.prev_snapshot = current
        return events

    # ---------------------- helpers ----------------------
    def _resolve_parent_name(self, ppid, prev, current):
        """Try resolve parent process name from snapshots."""
        if ppid in current:
            return current[ppid].get("name")
        if ppid in prev:
            return prev[ppid].get("name")
        return None

    def _make_event(self, etype, pid, proc, parent_name):
        """Generate event dictionary."""
        event = {
            "type": etype,
            "pid": pid,
            "ppid": proc.get("ppid"),
            "parent_name": parent_name,
            "process_name": proc.get("name"),
            "exe_path": proc.get("exe"),
            "username": proc.get("username"),
            "cmdline": proc.get("cmdline"),
            "hash_sha256": proc.get("hash_sha256"),
            "session_id": proc.get("session_id"),
            "ts": now_ts()
        }           
        events = {
            "detector": self.name,
            "event": event,
            "_monitor_ts": now_ts()
        }            
        self.logger.info(events)       
                
        return event