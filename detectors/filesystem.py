import os
import time
import threading
import ctypes
import ctypes.wintypes
import datetime
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # <-- patch import

class FileSystemDetector(BaseDetector):
    """
    Hybrid FileSystem detector
    - mode="snapshot" → polling diff (cross-platform, default)
    - mode="realtime" → event-based using ReadDirectoryChangesW (Windows only, via ctypes)
    """

    name = "fs"

    def __init__(
        self,
        paths=None,
        interval: float = 2.0,
        scan_recursive: bool = False,
        max_snapshot_depth: int = 3,
        watch_exts: list = None,
        exclude_dirs: list = None,      # <── NEW
        mode: str = "snapshot",
        output_callback=None,  # <--- NEW: optional callback to send event directly
        verbose=True
    ):
        super().__init__(interval)
        self.paths = list(paths or [])
        self.scan_recursive = bool(scan_recursive)
        self.max_snapshot_depth = int(max_snapshot_depth)
        self.watch_exts = set([e.lower() for e in (watch_exts or [])])
        self.exclude_dirs = [os.path.normcase(d) for d in (exclude_dirs or [])]  # <── normalize paths
        self.mode = mode.lower().strip()
        self.prev = {}
        self._stop_event = threading.Event()
        self._threads = []
        self._realtime_events = []
        self._event_state = {}  # track {file: (last_ts, seq)}
        self._callback = output_callback  # save callback for monitor queue
        self.verbose = verbose

        # ------------------ logger per-detector ------------------
        self.logger = DetectorLogger(self.name)
        #self.logger.info(f"FileSystemDetector initialized: mode={self.mode}, paths={self.paths}")

        if self.mode == "realtime":
            print("[*] FileSystemDetector running in REALTIME mode (ctypes watcher)")
        else:
            print("[*] FileSystemDetector running in SNAPSHOT mode")

    # --------------------- COMMON ---------------------
    def _should_watch_file(self, filepath):
        if not self.watch_exts:
            return True
        _, ext = os.path.splitext(filepath)
        return ext.lower() in self.watch_exts

    def _is_excluded(self, path):
        """Return True jika path termasuk ke daftar exclude_dirs."""
        norm = os.path.normcase(path)
        for ex in self.exclude_dirs:
            if ex and ex in norm:
                return True
        return False

    # --------------------- SNAPSHOT MODE ---------------------
    def _snapshot(self, paths=None, recursive=False, max_depth=None):
        if max_depth is None:
            max_depth = self.max_snapshot_depth
        snap = {}
        if not paths:
            paths = list(self.paths or [])
        for base in paths:
            try:
                base_abs = os.path.abspath(base)
                if not os.path.exists(base_abs) or self._is_excluded(base_abs):
                    continue
                if os.path.isfile(base_abs):
                    if self._should_watch_file(base_abs):
                        try:
                            st = os.path.getmtime(base_abs)
                            sz = os.path.getsize(base_abs)
                            if self._is_excluded(p):
                                continue                            
                            snap[base_abs] = (sz, st)
                        except Exception:
                            continue
                    continue
                if not recursive:
                    for entry in os.scandir(base_abs):
                        try:
                            if entry.is_file():
                                p = os.path.abspath(entry.path)
                                if not self._should_watch_file(p):
                                    continue
                                stat = entry.stat()
                                snap[p] = (stat.st_size, stat.st_mtime)
                        except Exception:
                            continue
                else:
                    for root, dirs, files in os.walk(base_abs):
                        rel = os.path.relpath(root, base_abs)
                        depth = 0 if rel == "." else rel.count(os.sep) + 1
                        if depth > max_depth:
                            dirs[:] = []
                            continue
                        for f in files:
                            try:
                                p = os.path.join(root, f)
                                if not self._should_watch_file(p):
                                    continue
                                snap[os.path.abspath(p)] = (
                                    os.path.getsize(p),
                                    os.path.getmtime(p),
                                )
                            except Exception:
                                continue
            except Exception:
                continue
        return snap

    def poll_snapshot(self):
        events = []
        snap = self._snapshot(paths=self.paths, recursive=self.scan_recursive)
        for p, meta in snap.items():
            if p not in self.prev:
                ev = {"type": "file_created", "path": p, "size": meta[0], "mtime": meta[1], "ts": now_ts()}
                events.append(ev)
                self.logger.info({"detector": self.name, "event": ev})                
            else:
                if meta != self.prev[p]:
                    ev = {"type": "file_modified", "path": p, "old": self.prev[p], "new": meta, "ts": now_ts()}
                    events.append(ev)
                    self.logger.info({"detector": self.name, "event": ev})                                        
        for p in list(self.prev.keys()):
            if p not in snap:
                ev = {"type": "file_deleted", "path": p, "old": self.prev[p], "ts": now_ts()}
                events.append(ev)
                self.logger.info({"detector": self.name, "event": ev})                
        self.prev = snap
        return events

    # --------------------- REALTIME MODE ---------------------
    def _watch_directory(self, path):
        FILE_LIST_DIRECTORY = 0x0001
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

        FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
        FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
        FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
        FILE_NOTIFY_CHANGE_SIZE = 0x00000008
        FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
        FILE_NOTIFY_CHANGE_CREATION = 0x00000040

        ACTIONS = {
            1: "file_added",
            2: "file_removed",
            3: "file_modified",
            4: "file_renamed_old",
            5: "file_renamed_new",
        }

        handle = ctypes.windll.kernel32.CreateFileW(
            ctypes.c_wchar_p(path),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle == -1:
            print(f"[!] Cannot open directory handle: {path}")
            return

        print(f"[*] Started realtime watcher for {os.path.basename(path) or path}")
        BUFFER_SIZE = 16384
        buf = ctypes.create_string_buffer(BUFFER_SIZE)
        bytes_returned = ctypes.wintypes.DWORD()

        while not self._stop_event.is_set():
            res = ctypes.windll.kernel32.ReadDirectoryChangesW(
                handle,
                ctypes.byref(buf),
                BUFFER_SIZE,
                True,
                FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_ATTRIBUTES
                | FILE_NOTIFY_CHANGE_SIZE
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_CREATION,
                ctypes.byref(bytes_returned),
                None,
                None,
            )
            if not res:
                time.sleep(0.5)
                continue

            offset = 0
            while offset < bytes_returned.value:
                next_entry_offset = int.from_bytes(buf[offset:offset+4], "little")
                action = int.from_bytes(buf[offset+4:offset+8], "little")
                name_length = int.from_bytes(buf[offset+8:offset+12], "little")
                name = buf[offset+12:offset+12+name_length].decode("utf-16le", errors="ignore").rstrip("\x00")
                full_path = os.path.join(path, name)

                # Skip jika termasuk folder exclude
                if self._is_excluded(full_path):
                    offset += next_entry_offset or bytes_returned.value
                    continue

                try:
                    st = os.stat(full_path)
                    size = st.st_size
                    mtime = datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
                    is_dir = os.path.isdir(full_path)
                    exists = True
                except FileNotFoundError:
                    size, mtime, is_dir, exists = None, None, None, False

                prev_ts, seq = self._event_state.get(full_path, (None, 0))
                now = time.time()
                delta_ms = int((now - prev_ts) * 1000) if prev_ts else 0
                seq += 1
                self._event_state[full_path] = (now, seq)

                if action == 1:
                    detail = "file created"
                elif action == 2:
                    detail = "file deleted"
                elif action == 3:
                    detail = "metadata updated" if delta_ms < 100 else "content modified"
                elif action in (4, 5):
                    detail = "file renamed"
                else:
                    detail = "unknown action"

                ACTION_CATEGORY = {
                    1: "creation",
                    2: "deletion",
                    3: "modification",
                    4: "rename",
                    5: "rename",
                }

                ev = {
                    "type": ACTIONS.get(action, "unknown"),
                    "file": full_path,
                    "action_code": action,
                    "size": size,
                    "mtime": mtime,
                    "is_dir": is_dir,
                    "exists": exists,
                    "ext": os.path.splitext(full_path)[1].lower(),
                    "sequence_id": seq,
                    "delta_ms": delta_ms,
                    "action_detail": detail,
                    "action_category": ACTION_CATEGORY.get(action, "other"),
                    "watcher_path": path,
                    "ts": now_ts(),
                }

                # Log event per-detector
                self.logger.info({"detector": self.name, "event": ev})

                # NEW: push directly to monitor queue via callback
                if callable(self._callback):
                    try:
                        self._callback({"detector": self.name, "event": ev})
                    except Exception as e:
                        print(f"[!] FS callback error: {e}")
                else:
                    self._realtime_events.append(ev)

                if self.verbose:
                    print(f"[FS-DEBUG] {detail}: {full_path} (seq={seq}, Δ={delta_ms}ms)")

                if next_entry_offset == 0:
                    break
                offset += next_entry_offset

        ctypes.windll.kernel32.CloseHandle(handle)

    def poll_realtime(self):
        evs = getattr(self, "_realtime_events", [])
        self._realtime_events = []
        return evs

    def poll(self):
        if self.mode == "snapshot":
            return self.poll_snapshot()
        else:
            if not getattr(self, "_threads", []):
                self.start_realtime()
                time.sleep(0.2)
            return self.poll_realtime()

    def start_realtime(self):
        self._realtime_events = []
        for p in self.paths:
            if not os.path.isdir(p):
                continue
            t = threading.Thread(
                target=self._watch_directory,
                args=(p,),
                daemon=True,
                name=f"watch-{os.path.basename(p)}",
            )
            t.start()
            self._threads.append(t)

    def stop_realtime(self):
        self._stop_event.set()
        time.sleep(0.5)
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=0.5)
