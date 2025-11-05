# monitor.py
import threading, time, json, os, zipfile, queue
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from collections import defaultdict

def now_ts():
    return datetime.utcnow().isoformat() + "Z"

class BaseDetector:
    name = "base"
    def __init__(self, interval: float = 2.0, mode: str = "snapshot"):
        """
        :param interval: polling interval (seconds)
        :param mode: "snapshot" (default) or "realtime"
        """
        self.interval = interval
        self.mode = mode  # can be changed at runtime

    def poll(self) -> List[Dict[str, Any]]:
        """Return list of event dicts. Implemented by concrete detectors."""
        return []

class Monitor:
    def __init__(self, output_callback: Optional[Callable[[Dict[str, Any]], None]]=None,
                 logfile: Optional[str]=None, max_size_mb: int=5,
                 per_detector_logs: bool=True, per_detector_dir: Optional[str]="logs"):
        self.detectors: List[BaseDetector] = []
        self.running = False
        self.threads: List[threading.Thread] = []
        self.output_callback = output_callback
        self.logfile = logfile
        self.max_size_mb = max_size_mb
        self._log_index = 0
        self.per_detector_logs = per_detector_logs
        self.per_detector_dir = per_detector_dir
        self._detector_indices: Dict[str, int] = {}
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()

        # mapping detector_name -> worker Thread (for status)
        self._worker_threads: Dict[str, threading.Thread] = {}

        if logfile:
            os.makedirs(os.path.dirname(logfile) or ".", exist_ok=True)
        if per_detector_logs and per_detector_dir:
            os.makedirs(per_detector_dir, exist_ok=True)

    # ---------------- log rotation ----------------
    def _rotate_file(self, filename: str, detector: Optional[str]=None):
        if not os.path.exists(filename):
            return filename
        size_mb = os.path.getsize(filename) / (1024*1024)
        if size_mb >= self.max_size_mb:
            if detector:
                idx = self._detector_indices.get(detector, 0)
                base, ext = os.path.splitext(filename)
                rotated = f"{base}_{idx}{ext}"
                self._detector_indices[detector] = idx + 1
            else:
                base, ext = os.path.splitext(filename)
                rotated = f"{base}_{self._log_index}{ext}"
                self._log_index += 1

            os.rename(filename, rotated)
            # zip kompres
            zipname = f"{rotated}.zip"
            with zipfile.ZipFile(zipname, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(rotated, os.path.basename(rotated))
            os.remove(rotated)

        return filename

    def _write_log(self, event: Dict[str, Any], detector: str):
        if self.logfile:
            self._rotate_file(self.logfile)
            with open(self.logfile, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")

        if self.per_detector_logs:
            if self.per_detector_dir:
                ddir = os.path.join(self.per_detector_dir, detector)
                os.makedirs(ddir, exist_ok=True)
                fname = os.path.join(ddir, f"{detector}.log")
            else:
                fname = f"{detector}.log"
            self._rotate_file(fname, detector)
            with open(fname, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")

    # ---------------- core ----------------
    def add_detector(self, det: BaseDetector):
        self.detectors.append(det)

    def _extract_root_detector(self, event: dict) -> str:
        """Ambil nama detector paling luar dari event nested."""
        d = event.get("detector", "unknown")
        inner = event.get("event")
        while isinstance(inner, dict) and "detector" in inner:
            d = inner["detector"]
            inner = inner.get("event")
        return d

    def _dispatch(self, event):
        # ambil event dari queue, kirim ke output_callback saja
        if self.output_callback:
            try:
                self.output_callback(event)
            except Exception:
                pass
        # log per-detector sekarang sudah handled di masing-masing detector


    # ===========================================================
    # Refactor: unified worker for snapshot vs realtime detectors
    # ===========================================================
    def _worker(self, det: BaseDetector):
        """
        Worker per detector (jalan di thread sendiri).
        Bedakan antara mode snapshot dan realtime.
        - snapshot → polling interval normal
        - realtime → polling cepat (misal 0.5s atau sesuai det.interval)
        """
        mode = getattr(det, "mode", "snapshot")
        interval = max(0.1, float(getattr(det, "interval", 2.0)))
        # fast_delay = smaller of (0.5s, interval). If det.interval < 0.5, fast_delay == det.interval
        fast_delay = min(0.5, interval)

        while self.running:
            try:
                evs = det.poll()
                for e in evs:
                    # [PATCH: FIX NESTED LOG] tandai event ini sudah final agar tidak dibungkus ulang
                    self._queue.put({"detector": det.name,"event": e, "_final": True})                    
                    #self._queue.put({"detector": det.name, "event": e})
            except Exception as e:
                # push an error event so dispatcher/caller can see it
                self._queue.put({
                    "detector": det.name,
                    "event": {"type": "error", "msg": str(e), "ts": now_ts()}
                })

            # beda perilaku antara realtime dan snapshot
            if mode == "realtime":
                time.sleep(fast_delay)
            else:
                time.sleep(interval)

    def _dispatcher(self):
        """Ambil event dari queue dan kirim ke log/output_callback."""
        while self.running:
            try:
                ev = self._queue.get(timeout=1)
                self._dispatch(ev)
            except queue.Empty:
                continue

    # ---------------- lifecycle ----------------
    def start(self):
        if self.running:
            return
        self.running = True

        # Start dispatcher (named for easier introspection)
        tdisp = threading.Thread(target=self._dispatcher, daemon=True, name="dispatcher")
        tdisp.start()
        self.threads.append(tdisp)

        # Start worker threads per detector and keep mapping
        for d in self.detectors:
            # --- PATCH: start realtime watchers if detector supports it ---
            if getattr(d, "mode", "snapshot") == "realtime" and hasattr(d, "start_realtime"):
                try:
                    d.start_realtime()
                    print(f"[*] Started realtime watcher for {d.name}")
                except Exception as e:
                    print(f"[!] Failed to start realtime watcher for {d.name}: {e}")

            # --- then start polling thread ---
            t = threading.Thread(target=self._worker, args=(d,), daemon=True, name=f"worker-{d.name}")
            t.start()
            self.threads.append(t)
            self._worker_threads[d.name] = t


    def stop(self):
        self.running = False
        time.sleep(0.2)

    # ---------------- introspection ----------------
    def get_detector_status(self) -> List[Dict[str, Any]]:
        """
        Return list of dicts: [{"detector": name, "thread_alive": bool, "interval": <seconds>, "mode": <str>}...]
        """
        status = []
        for d in self.detectors:
            name = d.name
            th = self._worker_threads.get(name)
            alive = bool(th and th.is_alive())
            status.append({
                "detector": name,
                "thread_alive": alive,
                "interval": getattr(d, "interval", None),
                "mode": getattr(d, "mode", "snapshot")
            })
        return status