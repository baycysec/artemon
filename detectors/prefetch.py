# prefetch.py (Artemon final)
import os, time
from datetime import datetime, timezone
from monitor import now_ts
from logger_util import DetectorLogger  # <--- patch ini

DEBUG = False

class PrefetchDetector:
    name = "prefetch"

    def __init__(self, interval: float = 3.0, skip_protected: bool = True):
        self.interval = interval
        self.skip_protected = skip_protected

        windir = os.environ.get("WINDIR", r"C:\Windows")
        userprofile = os.environ.get("USERPROFILE")

        self.paths = [os.path.join(windir, "Prefetch")]
        if userprofile:
            self.paths += [
                os.path.join(userprofile, "Downloads"),
                os.path.join(userprofile, "Recent"),
            ]

        self.logger = DetectorLogger(self.name)  # <--- patch: buat logger per-detector
        self._snapshot = {}
        self._init_snapshot()

    def _init_snapshot(self):
        for path in self.paths:
            if not os.path.exists(path):
                continue
            try:
                for f in os.listdir(path):
                    full = os.path.join(path, f)
                    if os.path.isfile(full):
                        self._snapshot[full] = os.path.getmtime(full)
            except (PermissionError, OSError):
                if DEBUG and not self.skip_protected:
                    raise

    def _get_file_timestamp(self, filepath):
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.utcfromtimestamp(mtime).replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            return None

    def _extract_exe_name(self, filepath):
        base = os.path.basename(filepath)
        return base.split("-")[0] if "-" in base else base

    # ---------------- Scan Logic ----------------
    def _scan_once(self):
        current_files = {}
        for path in self.paths:
            if not os.path.exists(path):
                continue
            try:
                files = os.listdir(path)
            except (PermissionError, OSError):
                if self.skip_protected:
                    continue
                else:
                    raise

            for f in files:
                full = os.path.join(path, f)
                if not os.path.isfile(full):
                    continue
                try:
                    mtime = os.path.getmtime(full)
                except (PermissionError, OSError):
                    continue

                current_files[full] = mtime
                if full not in self._snapshot:
                    self._snapshot[full] = mtime
                    self._log_change("CREATED", full)
                elif mtime != self._snapshot[full]:
                    old_mtime = self._snapshot[full]
                    self._snapshot[full] = mtime
                    self._log_change("MODIFIED", full, old_mtime)

        deleted_files = set(self._snapshot.keys()) - set(current_files.keys())
        for full in deleted_files:
            last_mtime = self._snapshot[full]
            self._log_change("DELETED", full, last_mtime)
            del self._snapshot[full]

    # ---------------- Logging ----------------
    def _log_change(self, change_type, filepath, old_mtime=None):
        event = {
            "type": f"file_{change_type.lower()}",
            "path": filepath,
            "exe_name": self._extract_exe_name(filepath)
        }             
                       
        if change_type in ("CREATED", "MODIFIED"):
            event["mtime_utc"] = self._get_file_timestamp(filepath)
            if change_type == "MODIFIED" and old_mtime:
                event["old_mtime_utc"] = datetime.utcfromtimestamp(old_mtime).replace(tzinfo=timezone.utc).isoformat()
        elif change_type == "DELETED":
            event["last_mtime_utc"] = datetime.utcfromtimestamp(old_mtime).replace(tzinfo=timezone.utc).isoformat() if old_mtime else None

        # Artemon final: pakai output_callback monitor
        if hasattr(self, "output_callback") and callable(self.output_callback):
            events = {
                "detector": self.name,
                "event": event,
                "_monitor_ts": now_ts()
            }            
            self.logger.info(events)  # <- ini penting, JSONFormatter akan otomatis serialize dict            
            self.output_callback(events)
        elif DEBUG:
            print(f"[Prefetch] {event}")

    # ---------------- Public Interface ----------------
    def scan_recursive(self):
        self._scan_once()
        return []

    def poll(self):
        return self.scan_recursive()
