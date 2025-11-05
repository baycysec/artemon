# detectors/lnk_realtime.py (FINAL for Artemon)
import os, time, threading, queue, ctypes, ctypes.wintypes, subprocess, re
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # gunakan ini


# ------------------ helper ------------------
def safe_subprocess(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, shell=False)
        return out.decode(errors='ignore')
    except:
        return ""

def resolve_lnk_target_powershell(path):
    ps = [
        "powershell", "-NoProfile", "-Command",
        f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{path}'); " \
        "if ($s.TargetPath) { Write-Output (\"$($s.TargetPath)||$($s.Arguments)\") }"
    ]
    out = safe_subprocess(ps).strip()
    if out:
        parts = out.split("||", 1)
        return {'target': parts[0], 'arguments': parts[1] if len(parts) > 1 else ''}
    return None

def resolve_lnk_target_heuristic(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        candidates = []
        for sep in (b"C:\\", b"c:\\", b"\\\\"):
            idx = data.find(sep)
            while idx != -1:
                sample = data[idx:idx+260]
                s = sample.split(b'\x00', 1)[0]
                try:
                    txt = s.decode('utf-8', errors='ignore')
                    if len(txt) > 3 and ('\\' in txt or '/' in txt):
                        candidates.append(txt)
                except:
                    pass
                idx = data.find(sep, idx+1)
        if candidates:
            return {'target': max(candidates, key=len), 'arguments': ''}
    except:
        pass
    return None

# ------------------ suspicious-arguments heuristic ------------------
SUSPICIOUS_TOKENS = [
    r"certutil", r"powershell", r"bitsadmin", r"curl", r"wget",
    r"invoke-webrequest", r"start-process", r"invoke-expression",
    r"download", r"http://", r"https://", r"ftp://"
]

_suspicious_re = re.compile("|".join(tok for tok in SUSPICIOUS_TOKENS), flags=re.IGNORECASE)

def is_suspicious_arguments(argstr: str) -> (bool, list):
    if not argstr:
        return (False, [])
    reasons = []
    for tok in SUSPICIOUS_TOKENS:
        if re.search(tok, argstr, flags=re.IGNORECASE):
            reasons.append(tok)
    return (len(reasons) > 0, reasons)

# ------------------ LNKDetector ------------------
class LNKDetector(BaseDetector):
    name = "lnk"

    def __init__(self, interval: float = 5.0, paths_to_watch=None, scan_drive=False,
                 drive_excludes=None, whitelist_file: str = None, auto_whitelist: bool = False,
                 baseline_batch_sleep: float = 0.1, baseline_progress_callback=None,
                 scan_recursive: bool = False):
        super().__init__(interval=0)  # interval 0 karena realtime
        user = os.environ.get('USERPROFILE', '')

        default = [
            os.path.expandvars(r"%APPDATA%\\Microsoft\\Windows\\Recent"),
            os.path.join(user, "Desktop"),
            os.path.join(user, "Downloads"),
            os.path.join(user, r"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            os.path.join(os.environ.get('PROGRAMDATA', r"C:\\ProgramData"), r"Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            os.path.join(os.environ.get('PUBLIC', r"C:\\Users\\Public"), "Desktop")
        ]
        self.paths = paths_to_watch or default
        self.scan_drive = bool(scan_drive)
        self.drive_excludes = drive_excludes or [r"C:\\Windows", r"C:\\Program Files", r"C:\\Program Files (x86)"]
        self.scan_recursive = bool(scan_recursive)
        self.seen = {}

        # whitelist
        self.whitelist_file = whitelist_file
        self.auto_whitelist = bool(auto_whitelist) and bool(whitelist_file)
        self.whitelist = set()
        self._whitelist_lock = threading.Lock()
        if whitelist_file and os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        s = line.strip()
                        if s:
                            self.whitelist.add(s.lower())
            except Exception:
                pass

        self._initial_baselined = False
        self._baseline_thread = None
        self._baseline_queue = queue.Queue()
        self.baseline_batch_sleep = float(baseline_batch_sleep)
        self._progress_cb = baseline_progress_callback        
        self.output_callback = None

        # ------------------ logger per-detector ------------------
        self.logger = DetectorLogger(self.name)
        #self.logger.info("LNKDetector initialized, watching paths: " + ", ".join(self.paths))
        #self.logger.info({"event": f"LnkDetector initialized, watching {join(self.paths)}"})


        if self.auto_whitelist:
            self._start_baseline_thread()

        # start watchers
        self._watch_threads = []
        for p in self.paths:
            if os.path.isdir(p):
                t = threading.Thread(target=self._watch_folder, args=(p,), daemon=True)
                t.start()
                self._watch_threads.append(t)

    # ------------------ whitelist helpers ------------------
    def _is_whitelisted(self, lnk_path, target):
        with self._whitelist_lock:
            if not self.whitelist:
                return False
            lp = (lnk_path or '').lower()
            tp = (target or '').lower()
            for w in self.whitelist:
                if w in lp or w in tp or lp == w or tp == w:
                    return True
        return False

    def _append_to_whitelist_file(self, entry):
        if not self.whitelist_file:
            return
        try:
            os.makedirs(os.path.dirname(self.whitelist_file) or '.', exist_ok=True)
        except Exception:
            pass
        try:
            with open(self.whitelist_file, 'a', encoding='utf-8') as f:
                f.write(entry + '\n')
            with self._whitelist_lock:
                self.whitelist.add(entry.lower())
            #self.logger.debug(f"Whitelist appended: {entry}")
            if self._progress_cb:
                try:
                    self._progress_cb(f"whitelist: appended {entry}")
                except Exception:
                    pass
        except Exception:
            pass

    # ------------------ baseline thread ------------------
    def _start_baseline_thread(self):
        if self._baseline_thread and self._baseline_thread.is_alive():
            return
        self._baseline_thread = threading.Thread(target=self._baseline_worker, daemon=True)
        self._baseline_thread.start()
        #self.logger.info("Baseline thread started")
        if self._progress_cb:
            try:
                self._progress_cb("baseline: started")
            except Exception:
                pass

    def _baseline_worker(self):
        try:
            candidates = set()
            for p in self.paths:
                if os.path.isdir(p):
                    try:
                        for entry in os.scandir(p):
                            if entry.is_file() and entry.name.lower().endswith('.lnk'):
                                candidates.add(entry.path)
                    except Exception:
                        continue
                else:
                    if os.path.isfile(p) and p.lower().endswith('.lnk'):
                        candidates.add(p)

            if self.scan_drive:
                try:
                    for f in self._scan_drive_for_lnks(r"C:\\"):
                        candidates.add(f)
                except Exception:
                    pass

            if self.whitelist_file:
                try:
                    os.makedirs(os.path.dirname(self.whitelist_file) or '.', exist_ok=True)
                    open(self.whitelist_file, 'a').close()
                except Exception:
                    pass

            total = len(candidates)
            if self._progress_cb:
                try:
                    self._progress_cb(f"baseline: resolving {total} candidates")
                except Exception:
                    pass

            batch = []
            processed = 0
            for lnk in sorted(candidates):
                try:
                    res = resolve_lnk_target_powershell(lnk) or resolve_lnk_target_heuristic(lnk)
                    target = res.get('target') if res else None
                    if target and (target.lower() not in self.whitelist):
                        batch.append(target)
                    if (lnk.lower() not in self.whitelist):
                        batch.append(lnk)
                except Exception:
                    continue

                processed += 1
                if len(batch) >= 10:
                    for e in batch:
                        self._append_to_whitelist_file(e)
                    batch = []
                    if self._progress_cb:
                        try:
                            self._progress_cb(f"baseline: processed {processed}/{total}")
                        except Exception:
                            pass
                    time.sleep(self.baseline_batch_sleep)

            for e in batch:
                self._append_to_whitelist_file(e)

        finally:
            self._initial_baselined = True
            #self.logger.info("Baseline thread finished")
            if self._progress_cb:
                try:
                    self._progress_cb("baseline: finished")
                except Exception:
                    pass

    # ------------------ watcher ------------------
    def _watch_folder(self, folder):
        FILE_LIST_DIRECTORY = 0x0001
        FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
        FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010

        hDir = ctypes.windll.kernel32.CreateFileW(
            ctypes.c_wchar_p(folder),
            FILE_LIST_DIRECTORY,
            0x00000007,
            None,
            3,
            0x02000000,
            None
        )
        if hDir == -1:
            self.logger.error(f"Failed to watch folder: {folder}")
            return

        buffer = ctypes.create_string_buffer(1024)
        bytes_returned = ctypes.wintypes.DWORD()

        while True:
            result = ctypes.windll.kernel32.ReadDirectoryChangesW(
                hDir,
                ctypes.byref(buffer),
                ctypes.sizeof(buffer),
                False,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                ctypes.byref(bytes_returned),
                None,
                None
            )
            if result:
                try:
                    for entry in os.scandir(folder):
                        if entry.is_file() and entry.name.lower().endswith('.lnk'):
                            st = os.path.getmtime(entry.path)
                            if self.seen.get(entry.path) == st:
                                continue
                            self.seen[entry.path] = st

                            res = resolve_lnk_target_powershell(entry.path) or {}
                            target = res.get('target')
                            args = res.get('arguments', '')

                            suspicious, reasons = is_suspicious_arguments(args)

                            event = {
                                "type": "lnk_detected",
                                "path": entry.path,
                                "mtime": time.ctime(st),
                                "target": target,
                                "arguments": args,
                                "suspicious": suspicious,
                                "suspicious_reason": reasons,
                                "ts": now_ts(),
                                "detector": self.name
                            }

                            self.logger.info({"detector": self.name, "event": event})

                            #if suspicious:
                            #    self.logger.warn(f"Suspicious LNK detected: reasons={reasons}")

                            # enqueue ke output_callback / queue
                            if self.output_callback and self.output_callback != self._queue.put:
                                try:
                                    self.output_callback(event)
                                except Exception:
                                    pass
                            else:
                                self._queue.put(event)
                except Exception:
                    continue

    # ------------------ poll fallback ------------------
    def poll(self):
        events = []
        while not self._queue.empty():
            events.append(self._queue.get())
        return events

    # ------------------ scan drive helper ------------------
    def _should_ignore_path(self, path):
        for ex in self.drive_excludes:
            try:
                if os.path.commonpath([os.path.abspath(path), os.path.abspath(ex)]) == os.path.abspath(ex):
                    return True
            except Exception:
                continue
        return False

    def _scan_drive_for_lnks(self, drive=r"C:\\"):
        found = []
        for root, dirs, files in os.walk(drive):
            if self._should_ignore_path(root):
                dirs[:] = []
                continue
            for f in files:
                if f.lower().endswith(".lnk"):
                    found.append(os.path.join(root, f))
        return found
