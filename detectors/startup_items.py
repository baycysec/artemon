# detectors/startup_items.py
import os
import winreg
import time
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # <-- patch import

# helper to read key values into dict
def read_key_values(root, subkey):
    out = {}
    try:
        with winreg.OpenKey(root, subkey) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                    out[name] = val
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return out

def list_startup_folders():
    res = []
    user_profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    app_start = os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    programdata_start = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    for p in (app_start, programdata_start):
        if os.path.exists(p):
            res.append(p)
    return res

def list_files_in_folders(folders):
    out = {}
    for f in folders:
        try:
            for fn in os.listdir(f):
                out[os.path.join(f, fn)] = os.path.getmtime(os.path.join(f, fn))
        except Exception:
            continue
    return out

class StartupItemsDetector(BaseDetector):
    name = "startup_items"

    def __init__(self, interval: float = 5.0):
        super().__init__(interval)
        # registry keys to monitor
        self.keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        self.prev_reg = {}
        self.logger = DetectorLogger(self.name)
        for root, sub in self.keys:
            self.prev_reg[f"{root}\\{sub}"] = read_key_values(root, sub)
        self.prev_files = list_files_in_folders(list_startup_folders())

    def poll(self):
        events = []
        # registry
        for root, sub in self.keys:
            keyid = f"{root}\\{sub}"
            curr = read_key_values(root, sub)
            prev = self.prev_reg.get(keyid, {})
            # added
            for name in curr:
                if name not in prev:
                    event = {
                        "type":"startup_added",
                        "where":"registry",
                        "key":sub,
                        "name":name,
                        "value":curr[name],
                        "ts":now_ts()  
                    }
                    self.logger.info({"detector": self.name, "event": event})
                    events.append(event)                    
                    
            # removed
            for name in prev:
                if name not in curr:
                    event = {
                        "type":"startup_removed",
                        "where":"registry",
                        "key":sub,
                        "name":name,
                        "old":prev[name],
                        "ts":now_ts()
                    }
                    self.logger.info({"detector": self.name, "event": event})
                    events.append(event)                    
                    
            # changed
            for name in curr:
                if name in prev and curr[name] != prev[name]:
                    event = {
                        "type":"startup_changed",
                        "where":"registry",
                        "key":sub,
                        "name":name,
                        "old":prev[name],
                        "new":curr[name],
                        "ts":now_ts()
                    }
                    self.logger.info({"detector": self.name, "event": event})
                    events.append(event)                    
                    
            self.prev_reg[keyid] = curr

        # startup folders
        folders = list_startup_folders()
        curr_files = list_files_in_folders(folders)
        # added
        for p in curr_files:
            if p not in self.prev_files:
                event = {
                    "type":"startup_added",
                    "where":"folder",
                    "path":p,
                    "mtime":time.ctime(curr_files[p]),
                    "ts":now_ts()
                }
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                    
                
        # removed
        for p in list(self.prev_files.keys()):
            if p not in curr_files:
                event = {
                    "type":"startup_removed",
                    "where":"folder",
                    "path":p,
                    "old_mtime":time.ctime(self.prev_files[p]),
                    "ts":now_ts()
                }
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                    
                
        # changed
        for p in curr_files:
            if p in self.prev_files and curr_files[p] != self.prev_files[p]:
                event = {
                    "type":"startup_changed",
                    "where":"folder",
                    "path":p,
                    "old_mtime":time.ctime(self.prev_files[p]),
                    "new_mtime":time.ctime(curr_files[p]),
                    "ts":now_ts()
                }
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                    
                
        self.prev_files = curr_files
        return events