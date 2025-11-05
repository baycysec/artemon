# registry.py (patched: realtime + snapshot fallback + recursive Services + whitelist + suspicious filter)

import subprocess, os, time, threading
from monitor import BaseDetector, now_ts
import ctypes
from ctypes import wintypes
from logger_util import DetectorLogger  # <--- patch ini
import winreg  # <<< diperlukan karena take_snapshot() memakai winreg

DEBUG = False   # set False setelah debug selesai

# ---------------- Config ----------------
DEFAULT_WHITELIST_FILE = r"logs\registry\registry_whitelist.txt"

SUSPICIOUS_PATH_PATTERNS = [
    r"\\temp\\", r"%temp%", r"\\appdata\\", r"\\users\\public\\", r"\\downloads\\",
    r"\\users\\", r"\\tmp\\"
]

SAFE_PREFIXES = [
    r"c:\\windows", r"c:\\program files", r"c:\\program files (x86)"
]

# ---------------- helpers ----------------
def safe_subprocess(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, shell=False)
        return out.decode(errors="ignore")
    except Exception as e:
        if DEBUG:
            print("[REG DEBUG] safe_subprocess error:", e, "cmd:", cmd)
        return ""

def _normalize_key_path(key: str) -> str:
    k = key.strip()
    k = k.replace("HKEY_CURRENT_USER", "HKCU")
    k = k.replace("HKEY_LOCAL_MACHINE", "HKLM")
    return k

def _parse_reg_output(out: str):
    res = {}
    if not out:
        return res
    current_key = None
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.upper().startswith("HKEY") or line.lower().startswith("key name"):
            current_key = line.strip()
            continue
        parts = line.strip().split(None, 2)
        if len(parts) == 1:
            name, typ, data = "(Default)", "", ""
        elif len(parts) == 2:
            name, typ, data = parts[0], parts[1], ""
        else:
            name, typ, data = parts[0], parts[1], parts[2]
        if current_key:
            fullname = f"{current_key}|{name}"
        else:
            fullname = name
        res[fullname] = (typ, data)
    return res

def load_whitelist(path):
    wl = set()
    if not path:
        return wl
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        wl.add(s.lower())
    except Exception as e:
        if DEBUG:
            print("[REG DEBUG] failed load whitelist:", e)
    return wl

def _is_path_suspicious(data: str) -> bool:
    if not data:
        return False
    d = data.lower().replace("/", "\\")
    if d.startswith("\\\\"):
        return True
    if "%" in d:
        for p in SUSPICIOUS_PATH_PATTERNS:
            if p in d:
                return True
    for p in SUSPICIOUS_PATH_PATTERNS:
        if p in d:
            return True
    if "\\" in d:
        for pref in SAFE_PREFIXES:
            if d.startswith(pref):
                return False
        return True
    return False

# ---------------- WinAPI bindings ----------------
advapi32 = ctypes.WinDLL("Advapi32.dll")
RegNotifyChangeKeyValue = advapi32.RegNotifyChangeKeyValue
RegNotifyChangeKeyValue.argtypes = [
    wintypes.HKEY, wintypes.BOOL, wintypes.DWORD, wintypes.HANDLE, wintypes.BOOL
]
RegNotifyChangeKeyValue.restype = wintypes.DWORD

HKEY_CLASSES_ROOT   = 0x80000000
HKEY_CURRENT_USER   = 0x80000001
HKEY_LOCAL_MACHINE  = 0x80000002
HKEY_USERS          = 0x80000003
HKEY_CURRENT_CONFIG = 0x80000005

REG_NOTIFY_CHANGE_NAME       = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET   = 0x00000004
REG_NOTIFY_CHANGE_SECURITY   = 0x00000008

def _open_hkey(key_path: str):
    if key_path.upper().startswith("HKCU"):
        return HKEY_CURRENT_USER
    elif key_path.upper().startswith("HKLM"):
        return HKEY_LOCAL_MACHINE
    return None

# ---------------- Detector ----------------
class RegistryKeyDetector(BaseDetector):
    """
    Registry detector with:
      - keys: list of key paths (e.g. HKCU\\Software\\...\\Run)
      - interval: poll interval
      - recursive_keys: set/list of keys to query with /s (for Services etc.)
      - whitelist_file: optional path to whitelist known-good value targets (one per line)
      - include_all_changes: if False (default), detector will still record full diff but only emit
        events marked suspicious=True if changes include suspicious items; if True, emit all changes.
      - auto_baseline: if True (default), the detector will take a baseline snapshot at startup and
        will NOT emit events for existing values present at startup. Only subsequent changes emit events.
    """
    name = "registry"

    def __init__(self, keys=None, interval: float = 2.0,
                 recursive_keys=None, whitelist_file: str = DEFAULT_WHITELIST_FILE,
                 include_all_changes: bool = False, realtime: bool = True,
                 auto_baseline: bool = True):
        super().__init__(interval)
        self.logger = DetectorLogger(self.name)  # <--- patch: buat logger per-detector
        self.keys = [_normalize_key_path(k) for k in (keys or [])]
        self.recursive_keys = set([_normalize_key_path(k) for k in (recursive_keys or [])])
        self.prev = {}                # map key -> parsed dict (fullname->(type,data))
        self.whitelist_file = whitelist_file
        self.whitelist = load_whitelist(whitelist_file)
        self.include_all_changes = bool(include_all_changes)
        self.realtime = bool(realtime)
        self.auto_baseline = bool(auto_baseline)
        self._threads = []
        # track which keys have had initial baseline applied
        self._baseline_done = {k: False for k in self.keys}

        if DEBUG:
            print("[REG DEBUG] init keys:", self.keys)
            print("[REG DEBUG] recursive_keys:", self.recursive_keys)
            print("[REG DEBUG] whitelist entries:", len(self.whitelist))
            print("[REG DEBUG] auto_baseline:", self.auto_baseline)

        # If realtime mode, create initial baseline (if enabled) then start watchers
        if self.realtime:
            if self.auto_baseline:
                # perform initial baseline for all keys to avoid emitting existing values as 'changes'
                self._initial_baseline()
            self._start_watchers()

    def take_snapshot(self):
        snapshot = {}
        for hive, path, prefix in self.targets:
            key_name = f"{prefix}\\{path}"
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                sub = {}
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        # normalize simple representation: keep raw value for now
                        sub[name] = value
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                snapshot[key_name] = sub
            except FileNotFoundError:
                snapshot[key_name] = {}
            except Exception as e:
                # if unexpected error, record empty to avoid crash
                snapshot[key_name] = {}
                if DEBUG:
                    print(f"[REG-SUM DEBUG] snapshot failed for {key_name}: {e}")
        return snapshot

    def detect_changes(self, old: dict, new: dict):
        """
        Compare old/new snapshot dicts and return list of human-readable messages
        or structured change dicts depending on summary_only flag.
        """
        msgs = []
        for key_path in set(new.keys()) | set(old.keys()):
            old_vals = old.get(key_path, {})
            new_vals = new.get(key_path, {})

            added = {k: v for k, v in new_vals.items() if k not in old_vals}
            deleted = {k: v for k, v in old_vals.items() if k not in new_vals}
            modified = {k: v for k, v in new_vals.items() if k in old_vals and old_vals[k] != v}

            if not (added or deleted or modified):
                continue

            # produce one message per change (string), but sent as event dict for monitor compatibility
            for k, v in added.items():
                msg = {
                    "type": "registry_change",
                    "op": "added",
                    "key": key_path,
                    "value_name": k,
                    "value": v,
                    "ts": now_ts()
                }
                # log and collect
                try:
                    self.logger.info({"detector": self.name, "event": msg})
                except Exception:
                    pass
                msgs.append(msg)
            
            for k, v in deleted.items():
                msg = {
                    "type": "registry_change",
                    "op": "deleted",
                    "key": key_path,
                    "value_name": k,
                    "value": old_vals.get(k),
                    "ts": now_ts()
                }
                # log and collect
                try:
                    self.logger.info({"detector": self.name, "event": msg})
                except Exception:
                    pass
                msgs.append(msg)
                
            for k, v in modified.items():
                msg = {
                    "type": "registry_change",
                    "op": "modified",
                    "key": key_path,
                    "value_name": k,
                    "old_value": old_vals.get(k),
                    "new_value": v,
                    "ts": now_ts()
                }
                # log and collect
                try:
                    self.logger.info({"detector": self.name, "event": msg})
                except Exception:
                    pass
                msgs.append(msg)
                
        return msgs

    def run(self):
        """
        Start snapshot loop. Emits events via output_callback (or _queue if available).
        This detector intentionally uses snapshots (polling) for simplicity.
        """
        # initial baseline
        try:
            self.prev_snapshot = self.take_snapshot()
        except Exception as e:
            if DEBUG:
                print("[REG-SUM DEBUG] initial snapshot failed:", e)
            self.prev_snapshot = {}

        if not self.realtime:
            return

        while not self._stop_event.is_set():
            time.sleep(self.poll_interval)
            try:
                current = self.take_snapshot()
                changes = self.detect_changes(self.prev_snapshot, current)
                for evt in changes:
                    # if summary_only produced dict with 'type' = registry_summary already,
                    # forward as-is to callback/queue
                    try:
                        if callable(self.output_callback):
                            self.output_callback(evt)
                        elif hasattr(self, "_queue"):
                            self._queue.put(evt)
                        else:
                            # fallback to printing for debug
                            if DEBUG:
                                print("[REG-SUM DEBUG] event:", evt)
                    except Exception:
                        # best-effort: swallow errors to keep loop alive
                        if DEBUG:
                            import traceback; traceback.print_exc()
                # update baseline
                self.prev_snapshot = current
            except Exception as e:
                if DEBUG:
                    print("[REG-SUM DEBUG] error in snapshot loop:", e)
                # wait a bit before retrying to avoid tight-error loop
                time.sleep(max(1.0, self.poll_interval))

    def stop(self):
        self._stop_event.set()

    def _initial_baseline(self):
        """
        Query each configured key and populate self.prev without emitting events.
        This prevents the detector from flooding when it first starts.
        """
        for k in self.keys:
            try:
                recursive = k in self.recursive_keys
                out = self._query_key(k, recursive=recursive)
                parsed = _parse_reg_output(out)
                self.prev[k] = parsed
                self._baseline_done[k] = True
                if DEBUG:
                    print(f"[REG DEBUG] baseline for {k}: entries={len(parsed)}")
            except Exception as e:
                if DEBUG:
                    print(f"[REG DEBUG] baseline failed for {k}: {e}")
            # small sleep to avoid hammering reg.exe on startup
            time.sleep(0.05)

    def _query_key(self, key: str, recursive: bool=False):
        if recursive:
            cmd = ["reg", "query", key, "/s"]
        else:
            cmd = ["reg", "query", key]
        return safe_subprocess(cmd)

    def _filter_diff_for_suspicious(self, diff: dict):
        suspicious = {}
        found = False
        for fullname, change in diff.items():
            newv = change.get("new")
            oldv = change.get("old")
            candidates = []
            if newv and len(newv) >= 2:
                candidates.append(newv[1])
            if oldv and len(oldv) >= 2:
                candidates.append(oldv[1])
            is_s = False
            for c in candidates:
                if c and isinstance(c, str) and c.strip().lower() in self.whitelist:
                    continue
                if _is_path_suspicious(c if c else ""):
                    is_s = True
                    break
            if is_s:
                suspicious[fullname] = change
                found = True
        return found, suspicious


    # ---------------- Realtime Watcher ----------------
    def _watch_key(self, key):
        # open exact subkey handle then call RegNotifyChangeKeyValue on it (see previous patch for bindings)
        RegOpenKeyExW = advapi32.RegOpenKeyExW
        RegOpenKeyExW.argtypes = [wintypes.HKEY, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HKEY)]
        RegOpenKeyExW.restype = wintypes.LONG
        RegCloseKey = advapi32.RegCloseKey
        RegCloseKey.argtypes = [wintypes.HKEY]
        RegCloseKey.restype = wintypes.LONG

        KEY_READ = 0x20019
        KEY_NOTIFY = 0x0010
        REGSAM = KEY_READ | KEY_NOTIFY

        # parse root & subpath
        root = None
        subpath = ""
        k = key.replace("/", "\\")
        up = k.upper()
        if up.startswith("HKCU\\") or up == "HKCU":
            root = HKEY_CURRENT_USER
            subpath = k[len("HKCU\\"):] if len(k) > 4 else ""
        elif up.startswith("HKLM\\") or up == "HKLM":
            root = HKEY_LOCAL_MACHINE
            subpath = k[len("HKLM\\"):] if len(k) > 4 else ""
        else:
            parts = k.split("\\", 1)
            if len(parts) == 2:
                root_token, rest = parts[0].upper(), parts[1]
                if root_token == "HKCU":
                    root = HKEY_CURRENT_USER
                    subpath = rest
                elif root_token == "HKLM":
                    root = HKEY_LOCAL_MACHINE
                    subpath = rest

        if root is None:
            if DEBUG:
                print(f"[REG DEBUG] unsupported root for {key}")
            return

        while True:
            # open the subkey handle for notifications (so we get real changes for that specific subkey)
            hkey = wintypes.HKEY()
            target_path = subpath if subpath else ""
            res = RegOpenKeyExW(root, target_path, 0, REGSAM, ctypes.byref(hkey))
            if res != 0:
                if DEBUG:
                    print(f"[REG DEBUG] RegOpenKeyExW failed for {key} (res={res}), retry in {self.interval}s")
                time.sleep(self.interval)
                continue

            # wait for change
            res_notify = RegNotifyChangeKeyValue(
                hkey,
                True if (key in self.recursive_keys) else False,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                None,
                False
            )
            if res_notify != 0:
                if DEBUG:
                    print(f"[REG DEBUG] RegNotifyChangeKeyValue failed for {key} (res={res_notify})")
                try:
                    RegCloseKey(hkey)
                except Exception:
                    pass
                time.sleep(self.interval)
                continue

            # changed -> query current snapshot and diff against prev
            try:
                recursive = key in self.recursive_keys
                out = self._query_key(key, recursive=recursive)
                parsed = _parse_reg_output(out)
            except Exception as e:
                if DEBUG:
                    print(f"[REG DEBUG] failed to query key after notify for {key}: {e}")
                parsed = {}

            old = self.prev.get(key, {})
            # If auto_baseline is enabled and we never baseline this key (edge case), treat this as baseline and skip emitting
            if self.auto_baseline and not self._baseline_done.get(key, False):
                self.prev[key] = parsed
                self._baseline_done[key] = True
                if DEBUG:
                    print(f"[REG DEBUG] baseline (post-notify) for {key}, skipping emit")
                try:
                    RegCloseKey(hkey)
                except Exception:
                    pass
                continue

            if parsed != old:
                diff = {}
                ops = {}  # per-fullname action: added|deleted|modified
                allnames = set(parsed.keys()) | set(old.keys())
                for name in sorted(allnames):
                    o = old.get(name)
                    n = parsed.get(name)
                    if o != n:
                        # record old/new as before
                        diff[name] = {"old": o, "new": n}
                        # determine action
                        if o is None and n is not None:
                            ops[name] = "added"
                        elif o is not None and n is None:
                            ops[name] = "deleted"
                        else:
                            # both exist but different -> modified
                            ops[name] = "modified"

                suspicious_found, suspicious_changes = self._filter_diff_for_suspicious(diff)

                # decide whether to emit event based on include_all_changes or suspicion
                if self.include_all_changes or suspicious_found:
                    evt = {
                        "type": "registry_changed",
                        #"detector": self.name,          # <- tambahkan ini
                        "key": key,
                        "diff": diff,
                        "ops": ops,                          # NEW: per-item action
                        "changes_count": len(diff),          # NEW: quick count
                        "suspicious": bool(suspicious_found),
                        "suspicious_changes": suspicious_changes,
                        "ts": now_ts()
                    }
                    self.logger.info({"detector": self.name, "event": evt})
                    
                    # emit via preferred channel
                    try:
                        if hasattr(self, "output_callback") and callable(self.output_callback):
                            self.output_callback(evt)
                        elif hasattr(self, "_queue"):
                            self._queue.put(evt)
                        elif DEBUG:
                            print(f"[REG DEBUG] event: {evt}")
                    except Exception as e:
                        if DEBUG:
                            print(f"[REG DEBUG] failed to emit event for {key}: {e}")

                else:
                    if DEBUG:
                        print(f"[REG DEBUG] changes detected but none suspicious for key={key}; skipping emit")

                # update snapshot
                self.prev[key] = parsed

            try:
                RegCloseKey(hkey)
            except Exception:
                pass

    def _start_watchers(self):
        for k in self.keys:
            t = threading.Thread(
                target=self._watch_key,
                args=(k,),
                daemon=True,
                name=self.name  # crucial for per-detector log routing
            )
            t.start()
            self._threads.append(t)
            if DEBUG:
                print(f"[REG DEBUG] started realtime watcher for {k}")

    # ---------------- Optional polling fallback ----------------
    def poll(self):
        """
        For snapshot mode (realtime==False) or manual polling: behave similarly but
        don't emit initial snapshot when auto_baseline is True.
        """
        if self.realtime:
            return []  # realtime mode already emits events

        events = []
        for k in self.keys:
            recursive = k in self.recursive_keys
            out = self._query_key(k, recursive=recursive)
            parsed = _parse_reg_output(out)

            # If this is the first time and auto_baseline True -> do not emit snapshot event
            if k not in self.prev:
                if parsed and not self.auto_baseline:
                    event = {
                        "type":"registry_snapshot", 
                        "key":k, 
                        "values":parsed, 
                        "ts": now_ts()
                    }                        
                    self.logger.info({"detector": self.name, "event": event})
                    events.append(event)    
                    
                # record baseline silently
                self.prev[k] = parsed
                self._baseline_done[k] = True
                continue

            old = self.prev.get(k, {})
            if parsed != old:
                diff = {}
                ops = {}  # per-fullname action: added|deleted|modified
                allnames = set(parsed.keys()) | set(old.keys())
                for name in sorted(allnames):
                    o = old.get(name)
                    n = parsed.get(name)
                    if o != n:
                        # record old/new as before
                        diff[name] = {"old": o, "new": n}
                        # determine action
                        if o is None and n is not None:
                            ops[name] = "added"
                        elif o is not None and n is None:
                            ops[name] = "deleted"
                        else:
                            # both exist but different -> modified
                            ops[name] = "modified"

                suspicious_found, suspicious_changes = self._filter_diff_for_suspicious(diff)

                # decide whether to emit event based on include_all_changes or suspicion
                if self.include_all_changes or suspicious_found:
                    evt = {
                        "type": "registry_changed",
                        "key": key,
                        "diff": diff,
                        "ops": ops,                          # NEW: per-item action
                        "changes_count": len(diff),          # NEW: quick count
                        "suspicious": bool(suspicious_found),
                        "suspicious_changes": suspicious_changes,
                        "ts": now_ts()
                    }
                    self.logger.info({"detector": self.name, "event": evt})

                    # emit via preferred channel
                    try:
                        if hasattr(self, "output_callback") and callable(self.output_callback):
                            self.output_callback(evt)
                        elif hasattr(self, "_queue"):
                            self._queue.put(evt)
                        elif DEBUG:
                            print(f"[REG DEBUG] event: {evt}")
                    except Exception as e:
                        if DEBUG:
                            print(f"[REG DEBUG] failed to emit event for {key}: {e}")

                else:
                    if DEBUG:
                        print(f"[REG DEBUG] changes detected but none suspicious for key={key}; skipping emit")

                # update snapshot
                self.prev[key] = parsed