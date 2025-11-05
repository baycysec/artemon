# detectors/wmi_subscription.py
import subprocess, json
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # <-- patch import

def safe_ps(cmd):
    try:
        #out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        # tambahkan flags PowerShell biar lebih bersih & non-interaktif
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"] + cmd,
            stderr=subprocess.DEVNULL
        )
        return out.decode(errors="ignore")
    except Exception:
        return ""

def extract_json_from_output(out: str):
    """Ekstraksi JSON mentah dari output PowerShell yang kadang berisi noise."""
    if not out:
        return None
    s = out.strip()
    # cari indeks pertama '[' atau '{'
    idx_bracket = min([i for i in (s.find('['), s.find('{')) if i != -1], default=-1)
    if idx_bracket == -1:
        return None
    candidate = s[idx_bracket:]
    try:
        return json.loads(candidate)
    except Exception:
        # fallback: ambil sampai last bracket
        last_idx = max(candidate.rfind(']'), candidate.rfind('}'))
        if last_idx != -1:
            try:
                return json.loads(candidate[:last_idx+1])
            except Exception:
                return None
        return None

def normalize(data):
    """Pastikan output jadi list JSON valid, parse kalau string JSON."""
    if isinstance(data, str):
        trimmed = data.strip()
        if trimmed.startswith('{') or trimmed.startswith('['):
            try:
                data = json.loads(trimmed)
            except Exception:
                pass
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]

def get_wmi_subscriptions():
    # Query filters, consumers, bindings; return combined list
    ps = [
        "Get-CimInstance -Namespace root\\subscription -Class __EventFilter | ForEach-Object { [pscustomobject]@{Name=$_.Name; Query=$_.Query; QueryLanguage=$_.QueryLanguage; EventNamespace=$_.EventNamespace} } | ConvertTo-Json -Compress",
        "Get-CimInstance -Namespace root\\subscription -Class CommandLineEventConsumer | ForEach-Object { [pscustomobject]@{Name=$_.Name; CommandLineTemplate=$_.CommandLineTemplate} } | ConvertTo-Json -Compress",
        "Get-CimInstance -Namespace root\\subscription -Class __FilterToConsumerBinding | ForEach-Object { $f=($_.Filter -as [string]) -replace '.*Name=\"([^\"]+)\".*','$1'; $c=($_.Consumer -as [string]) -replace '.*Name=\"([^\"]+)\".*','$1'; [pscustomobject]@{Filter=$f; Consumer=$c} } | ConvertTo-Json -Compress"
    ]

    results = {}
    for i, snippet in enumerate(ps):
        out = safe_ps([snippet])
        # debug log (optional tapi sangat berguna)
        # print(f"[debug] part_{i}: {out[:300]}")
        
        parsed = None
        try:
            parsed = json.loads(out)
        except Exception:
            parsed = extract_json_from_output(out)

        results[f"part_{i}"] = parsed if parsed is not None else out.strip()
    return results

# 🔹 Tambahkan compare_part di sini
# 🔹 compare_part dipanggil oleh poll() untuk bandingkan hasil antar snapshot
def compare_part(self, prev, curr, part, events):
    if isinstance(prev, list) and isinstance(curr, list):
        prev_map = {json.dumps(p, sort_keys=True): p for p in prev}
        curr_map = {json.dumps(c, sort_keys=True): c for c in curr}
        for k in set(prev_map) | set(curr_map):
            if k not in prev_map:
                event = {
                    "type":"wmi_added",
                    "part":part,
                    "new":curr_map[k],
                    "ts":now_ts()
                }                
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                
            elif k not in curr_map:
                event = {
                    "type":"wmi_removed",
                    "part":part,
                    "old":prev_map[k],
                    "ts":now_ts()
                }                
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                
                
    elif prev != curr:
        event = {
            "type":"wmi_changed",
            "part":part,
            "old":prev,
            "new":curr,
            "ts":now_ts()
        }                
        self.logger.info({"detector": self.name, "event": event})
        events.append(event)                
        
class WmiSubscriptionDetector(BaseDetector):
    name = "wmi_subscription"

    def __init__(self, interval: float = 30.0):
        super().__init__(interval)
        self.prev = get_wmi_subscriptions()
        self.logger = DetectorLogger(self.name)  # per-detector logger (patch logging sistem baru)

    def poll(self):
        events = []
        curr = get_wmi_subscriptions()

        # 🔹 ganti simple compare → pakai compare_part
        for key in set(list(curr.keys()) + list(self.prev.keys())):
            prev = normalize(self.prev.get(key, []))
            new = normalize(curr.get(key, []))
            compare_part(self, prev, new, key, events)

        self.prev = curr
        return events