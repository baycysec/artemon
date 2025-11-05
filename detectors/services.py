# detectors/services.py
import os
import subprocess
import time
import winreg
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # <-- patch import

def safe_subprocess(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, shell=False)
        return out.decode(errors="ignore")
    except Exception:
        return ""

def query_sc_status(service_name):
    try:
        out = safe_subprocess(["sc", "query", service_name])
        # parse STATE line e.g. "STATE              : 4  RUNNING"
        for line in out.splitlines():
            if line.strip().startswith("STATE"):
                return line.split(":",1)[1].strip()
    except Exception:
        pass
    return None

def query_sc_config(service_name):
    try:
        out = safe_subprocess(["sc", "qc", service_name])
        return out
    except Exception:
        return None

def read_services_registry():
    base = r"SYSTEM\CurrentControlSet\Services"
    
    services = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as h:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(h, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(h, name) as sk:
                        try:
                            image, _ = winreg.QueryValueEx(sk, "ImagePath")
                        except Exception:
                            image = None
                        try:
                            start, _ = winreg.QueryValueEx(sk, "Start")
                        except Exception:
                            start = None
                        try:
                            type_, _ = winreg.QueryValueEx(sk, "Type")
                        except Exception:
                            type_ = None
                        services[name] = {"ImagePath": image, "Start": start, "Type": type_}
                except Exception:
                    continue
    except Exception:
        pass
    return services

class ServicesDetector(BaseDetector):
    name = "services"

    def __init__(self, interval: float = 10.0):
        super().__init__(interval)
        self.prev = read_services_registry()
        self.logger = DetectorLogger(self.name)

    def poll(self):
        events = []
        curr = read_services_registry()

        # created
        for svc in curr:
            if svc not in self.prev:
                ev = {"type":"service_created","service":svc,"meta":curr[svc],"ts":now_ts()}
                self.logger.info({"detector": self.name, "event": ev})
                # also get runtime status if possible
                ev["status"] = query_sc_status(svc)
                events.append(ev)

        # removed
        for svc in list(self.prev.keys()):
            if svc not in curr:
                event = {
                    "type":"service_removed",
                    "service":svc,
                    "old":self.prev[svc],
                    "ts":now_ts()
                }                
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)

        # changed
        for svc in curr:
            if svc in self.prev and curr[svc] != self.prev[svc]:
                ev = {"type":"service_changed","service":svc,"old":self.prev[svc],"new":curr[svc],"ts":now_ts()}
                self.logger.info({"detector": self.name, "event": ev})
                ev["status"] = query_sc_status(svc)
                events.append(ev)

        # update snapshot
        self.prev = curr
        return events
