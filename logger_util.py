# logger_util.py
# Artemon DetectorLogger - Realtime JSON Logging (Final)
# Usage: logger = DetectorLogger("process"); logger.info({"event": {...}})

import os
import threading
import time
import zipfile
import json

class DetectorLogger:
    """
    Lightweight modular logger for each detector.
    Writes JSON per event.
    Automatically creates folders, rotates logs by size, thread-safe.
    """

    _lock = threading.Lock()  # Global lock to avoid concurrent writes

    def __init__(self, detector_name, base_dir="logs", max_size=1024*1024, backup_count=3):
        """
        detector_name : str  -> e.g. 'lnk', 'filesystem', 'process'
        base_dir      : str  -> base directory for logs
        max_size      : int  -> log rotation threshold in bytes
        backup_count  : int  -> number of rotated archives to keep
        """
        self.detector_name = detector_name
        self.base_dir = os.path.join(base_dir, detector_name)
        self.log_path = os.path.join(self.base_dir, f"{detector_name}.log")
        self.max_size = max_size
        self.backup_count = backup_count

        os.makedirs(self.base_dir, exist_ok=True)

    def _timestamp(self):
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

    def _rotate_log(self):
        """Rotate and zip old log if it exceeds max_size"""
        if not os.path.exists(self.log_path):
            return
        if os.path.getsize(self.log_path) < self.max_size:
            return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        zip_name = os.path.join(self.base_dir, f"{self.detector_name}_{timestamp}.zip")
        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(self.log_path, arcname=f"{self.detector_name}.log")

        # Clear original log
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write(f"[{self._timestamp()}] INFO Log rotated -> {zip_name}\n")

        self._cleanup_old_archives()

    def _cleanup_old_archives(self):
        """Keep only latest N zip logs"""
        zips = sorted(
            [f for f in os.listdir(self.base_dir) if f.endswith(".zip")],
            key=lambda x: os.path.getmtime(os.path.join(self.base_dir, x))
        )
        if len(zips) > self.backup_count:
            for old_zip in zips[:-self.backup_count]:
                os.remove(os.path.join(self.base_dir, old_zip))

    def write(self, msg):
        """Thread-safe JSON log write"""
        with self._lock:
            self._rotate_log()
            with open(self.log_path, "a", encoding="utf-8") as f:
                json.dump(msg, f, default=str)
                f.write("\n")  # ensure one JSON object per line

    # Convenience shortcuts
    def info(self, msg): self.write(msg)
    def warn(self, msg): self.write({"level": "WARN", **msg} if isinstance(msg, dict) else {"message": msg})
    def error(self, msg): self.write({"level": "ERROR", **msg} if isinstance(msg, dict) else {"message": msg})
    def debug(self, msg): self.write({"level": "DEBUG", **msg} if isinstance(msg, dict) else {"message": msg})
