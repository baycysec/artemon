# main.py
import json, os, time, sys, random, shutil
from monitor import Monitor

# ==========================================================
# 🅰️ BANNER & BASIC UTILITIES
# ==========================================================
BANNERS = [
r"""
                _       __  __                 _    _       _                      __      ___     _             
     /\        | |     |  \/  |            _  | |  | |     | |                     \ \    / (_)   (_)            
    /  \   _ __| |_ ___| \  / | ___  _ __ (_) | |__| | ___ | |_ __ ___   ___  ___   \ \  / / _ ___ _  ___  _ __  
   / /\ \ | '__| __/ _ \ |\/| |/ _ \| '_ \    |  __  |/ _ \| | '_ ` _ \ / _ \/ __|   \ \/ / | / __| |/ _ \| '_ \ 
  / ____ \| |  | ||  __/ |  | | (_) | | | |_  | |  | | (_) | | | | | | |  __/\__ \    \  /  | \__ \ | (_) | | | |
 /_/    \_\_|   \__\___|_|  |_|\___/|_| |_(_) |_|  |_|\___/|_|_| |_| |_|\___||___/     \/   |_|___/_|\___/|_| |_|
                                                                                                                 
"""
]

def print_banner(version="0.1.1", tagline="learn • monitor • inspect", authors=None):
    banner = random.choice(BANNERS)
    authors = "IB [Ical n Brandy]"
    print(banner)
    print(f"Version: {version}")
    print(tagline)
    print(f"Authors: {authors}")
    print()

# callback yang menerima event dicts dari monitor (existing)
def print_cb(event):
    """Default output callback for monitor"""
    import json
    print(json.dumps(event, default=str))


# ==========================================================
# 🅱️ CONFIG FACTORIES (lazy builder functions)
# ==========================================================
def get_lnk_config():
    lnk_scan_drive = False  # True kalau mau scan seluruh C:\ (berat) => Learning Mode
    lnk_excludes = [r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)"]

    # Pastikan folder logs/lnk ada atau bisa dibuat; gunakan raw string untuk path
    lnk_whitelist_file = r"logs\lnk\lnk_whitelist.txt"   # file newline-separated
    lnk_auto_baseline = True  # True untuk membuat baseline otomatis pada first run
    lnk_baseline_batch_sleep = 0.05
    lnk_scan_recursive = True   # False = default cepat (os.listdir)
                                 # True  = learning mode recursive (os.walk)

    # progress callback untuk baseline thread (simple)
    def baseline_progress(msg):
        # msg adalah string yang dikirim oleh baseline thread
        print(f"[LNK BASELINE] {msg}")

    # progress callback - reuse baseline_progress if defined, else no-op
    try:
        callback = baseline_progress
    except NameError:
        callback = lambda msg: None

    return {
        "interval": 1.0, # 5
        "scan_drive": lnk_scan_drive,
        "drive_excludes": lnk_excludes,
        "whitelist_file": lnk_whitelist_file,
        "auto_whitelist": lnk_auto_baseline,
        "baseline_batch_sleep": lnk_baseline_batch_sleep,
        "baseline_progress_callback": callback,
        "scan_recursive": lnk_scan_recursive
    }

def get_filesystem_config():
    # build paths lazily list berdasarkan user aktif (this used to run at import time)
    INCLUDE_PUBLIC = True        # tambahkan C:\Users\Public
    INCLUDE_ALL_USERS = False    # kalau True => tambahkan folder Downloads/Desktop/Temp/Documents untuk tiap user (lebih banyak noise)
    USER_SUBPATHS = ["Downloads", "Desktop", os.path.join("AppData", "Local", "Temp"), "Documents"]
    #WATCH_EXTS = [".lnk", ".exe", ".ps1", ".bat", ".dll"]  # optional filter; set [] or None to watch all
    WATCH_EXTS = []  # optional filter; set [] or None to watch all

    user = os.environ.get("USERPROFILE") or os.path.join(os.path.expanduser("~"))
    paths = [
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "AppData", "Local", "Temp"),
        os.path.join(user, "Documents")
    ]

    # tambahkan Public jika ada
    # add public root and a couple of common public subfolders
    if INCLUDE_PUBLIC:
        public_path = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"))
        if os.path.exists(public_path):
            # add public root
            paths.append(public_path)
            # add common public subfolders
            for sub in ("Desktop", "Downloads"):
                psub = os.path.join(public_path, sub)
                if os.path.exists(psub):
                    paths.append(psub)

    # optional: tambahkan subfolders untuk semua users di C:\Users (be careful: this can be noisy)
    if INCLUDE_ALL_USERS:
        users_root = os.path.join(os.path.splitdrive(user)[0] + os.sep, "Users")
        # exclude some system profiles
        exclude = {"Default", 
                   "Default User", 
                   "All Users", 
                   "Public", 
                   "desktop.ini", 
                   "DefaultAccount", 
                   "WDAGUtilityAccount"}
        try:
            if os.path.exists(users_root):
                for entry in os.listdir(users_root):
                    if entry in exclude:
                        continue
                    userdir = os.path.join(users_root, entry)
                    if not os.path.isdir(userdir):
                        continue
                    for sub in USER_SUBPATHS:
                        p = os.path.join(userdir, sub)
                        if os.path.exists(p):
                            paths.append(p)
        except Exception as e:
            print(f"[!] Gagal scanning Users folder: {e}")
            
    # keep only existing paths and remove duplicates while preserving order
    # --- normalize and dedupe preserving order, with debug output ---
    seen = set()
    final_paths = []
    
    #print("[*] Filesystem candidate paths (raw):", flush=True)
    for idx, pp in enumerate(paths, start=1):
        try:
            ap = os.path.abspath(pp)
        except Exception:
            ap = pp
        exists = os.path.exists(ap)
        #print(f"  {idx:2d}. {ap!r} -> exists={exists}", flush=True)
        if ap and ap not in seen and exists:
            seen.add(ap)
            final_paths.append(ap)
    
    print("[*] Filesystem monitor paths (final):", flush=True)
    if final_paths:
        for p in final_paths:
            print("  -", p, flush=True)
    else:
        print("  (none found) - check user profile / PUBLIC folder / INCLUDE flags", flush=True)

    return {
        "paths": final_paths,
        "interval": 2.0,
        "scan_recursive": False,
        "max_snapshot_depth": 3,
        "watch_exts": WATCH_EXTS,
        "mode": "realtime",  # snapshot | realtime
        "verbose": False
    }

def get_registry_config():
    REG_KEYS = [
        # per-user/machine Run keys
        
        #  AWAL fitur di pisah agar tidak berat di registry detector
        # service detector
        # Services (monitor presence/changes for new services/drivers), fitur di pisah agar tidak berat di registry detector
        #r"HKLM\SYSTEM\CurrentControlSet\Services",

        # startup_item detector
        #r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        #r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        #r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",

        # RunOnce
        #r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        #r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        #r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        # AKHIR fitur di pisah agar tidak berat di registry detector
        
        # IFEO (Image File Execution Options) - debugger hijacks
        #r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",

        # AppInit_DLLs
        #r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",

        # Winlogon / Userinit / Shell (be careful)
        #r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",

        # Active Setup (per-user installers)
        #r"HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components",

        # StartupApproved (Windows 8+) - optional/advanced
        #r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        #r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",

        # Browser Helper Objects (Internet Explorer)
        #r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        
        # berhubungan dengan Scheduled Tasks (tapi kita sudah punya detector task). Bisa dipakai untuk cross-check.
        ##r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        ##r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",   
        
        ###WMI EVENT SUBSCRIPTIONS
        ##r"HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\Autorecover MOFs",
        ##r"HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\Autorecover MOFs\LastWrite",

        # WMI Event Filters
        ##r"HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\Autorecover MOFs",
        
        ###PowerShell History
        ##r"HKCU\Software\Microsoft\PowerShell\PSReadLine\ConsoleHost_history",

        ###PowerShell Execution Policy
        ##r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy",
        ##r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell",

        ###UserAssist
        ##r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",

        ###RecentApps
        ##r"HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps",

        ###AMCache (Program Execution):
        ##r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",

        ###FILE & DOCUMENT EVIDENCE
        ##r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        ##r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        
        ### Config malware XXX
        # reg query "HKCU\Control Panel\Personalization\Desktop Slideshow"
        # reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes"
        r"HKCU\Control Panel\Desktop",        
        r"HKCU\Control Panel\Personalization\Desktop Slideshow",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes",
    ]

    RECURSIVE_KEYS = [
        r"HKLM\SYSTEM\CurrentControlSet\Services"
    ]
    
    return {
        "keys": REG_KEYS,
        "interval": 2.0,
        "recursive_keys": RECURSIVE_KEYS,
        "whitelist_file": r"logs\registry\registry_whitelist.txt",
        "include_all_changes": False  # <<< sementara aktifkan semua perubahan untuk debugging
    }

def get_eventlog_config():
    '''
    alur urutannya simulasi run as :
    4648 => percobaan login dengan runas
    4625 => gagal login
    4624 => login sukses
    4672 => special logon
    4634 => logoff    
    '''
    # Setting None jika ingin tidak ada filter Event ID
    logs_config = {
        #"Security": [4624, 4625, 4634, 4648, 4688, 4689, 4672, 1102],
        "Security": None,
        "System": None,
        #"System": [7045, 7036, 7001],
        #"Application": [1001],
        "Application": None,
        "Microsoft-Windows-WMI-Activity/Operational": None,
        "Microsoft-Windows-TaskScheduler/Operational": [106,140,141,110,111],
        "Microsoft-Windows-PowerShell/Operational": [4104],
        
        # if Sysmon installed:
        #"Microsoft-Windows-Sysmon/Operational": [1,3,7,11]
    }                 
    
    return {
        "logs_config": logs_config,
        "interval": 5.0,
        "max_events_per_log": 50
    }


# ==========================================================
# 🅲️ DETECTOR REGISTRY
# ==========================================================
# format: shortname -> (module_path, class_name, default_kwargs)
DETECTOR_REGISTRY = {
    "process":   ("detectors.process", "ProcessDetector", None), # OK
    #"process": ("detectors.process", "ProcessDetector", {"interval": 2.0, "mode": "realtime"}), # 
    "netstat":   ("detectors.netstat", "NetstatDetector", {"interval": 5.0}), # OK
    "filesystem": ("detectors.filesystem", "FileSystemDetector", None),  # ensure `paths` defined earlier # OK
    "registry":  ("detectors.registry", "RegistryKeyDetector", None), # OK
    "eventlog":  ("detectors.eventlog", "SimpleEventLogDetector", None), # OK
    "lnk":       ("detectors.lnk", "LNKDetector", None), # OK
    "prefetch":  ("detectors.prefetch", "PrefetchDetector", {"interval": 3.0, "log_callback": None}), # 60, OK
    "schtask":   ("detectors.schtask", "ScheduledTaskDetector", {"interval": 5.0}), #OK
    "recyclebin": ("detectors.recyclebin", "RecycleBinDetector", {"interval":5.0, "scan_all_drives":True}),        
    "services": ("detectors.services", "ServicesDetector", {"interval":5.0}),        
    "startup items": ("detectors.startup_items", "StartupItemsDetector", {"interval":5.0}),            
    "wmi subscription": ("detectors.wmi_subscription", "WmiSubscriptionDetector", {"interval":5.0}),        
}

# ==========================================================
# 🅳️ INTERACTIVE SELECTION
# ==========================================================
def choose_detectors_interactive():
    """Interactive detector selection menu"""
    names = list(DETECTOR_REGISTRY.keys())
    
    while True:
        print("\n" + "="*50)
        print("🛡️  DIGITAL FORENSIC DETECTOR SELECTION")
        print("="*50)    

        #print("\n=== Choose detectors to enable ===")
        for i, n in enumerate(names, 1):
            print(f"{i}. {n}")
            
        print("\nOptions:")
        print("  a. Enable ALL detectors")
        print("  x. Exit program")
        print("-" * 50)
        choice = input("Enter selection (comma-separated numbers or 'a'): ").strip()

        if not choice:
            print("[!] No input provided — fallback to ALL detectors.")
            return set(names)

        if choice.lower() == 'a':
            return set(names)
        if choice.lower() == 'x':
            print("Exiting. Stay secure! 🔒")
            sys.exit(0)
        
        # Try to parse comma-separated numeric choices
        tokens = [t.strip() for t in choice.split(",") if t.strip()]
        indices = []
        invalid_tokens = []

        for t in tokens:
            if t.isdigit():
                num = int(t)
                if 1 <= num <= len(names):
                    indices.append(num)
                else:
                    invalid_tokens.append(t)
            else:
                invalid_tokens.append(t)

        if invalid_tokens:
            print(f"[!] Invalid entries detected: {', '.join(invalid_tokens)}. Please try again.")
            continue

        if not indices:
            print("[!] No valid selections made. Please try again.")
            continue

        chosen = {names[i - 1] for i in indices}
        return chosen

# ==========================================================
# 🅴️ DETECTOR INITIALIZATION & MONITOR STARTUP
# ==========================================================
def init_detector(shortname, mon):
    """Initialize detector with correct config and callback setup (universal, race-safe)."""
    module_path, class_name, init_kwargs = DETECTOR_REGISTRY[shortname]

    # 1️⃣ Ambil config function get_<detector>_config() jika ada
    config_func_name = f"get_{shortname.replace(' ', '_')}_config"
    if config_func_name in globals():
        init_kwargs = globals()[config_func_name]()
    else:
        init_kwargs = dict(init_kwargs or {})

    # 2️⃣ Import class detector
    mod = __import__(module_path, fromlist=[class_name])
    cls = getattr(mod, class_name)

    # 3️⃣ Filter init_kwargs supaya hanya parameter valid untuk __init__
    from inspect import signature
    sig = signature(cls.__init__)
    valid_keys = set(sig.parameters.keys())
    filtered_kwargs = {k: v for k, v in (init_kwargs or {}).items() if k in valid_keys}

    # 4️⃣ Pas inject log_callback untuk PrefetchDetector
    #if shortname == "prefetch":
    #    filtered_kwargs["log_callback"] = mon.output_callback  # aman, diteruskan ke __init__


    # 4️⃣ Buat instance secara aman (pre-inject _queue & callback)
    try:
        det = cls.__new__(cls)

        # pre-inject queue & callback sebelum __init__ dijalankan
        setattr(det, "_queue", mon._queue)
        try:
            setattr(det, "output_callback", mon._queue.put)
        except Exception:
            pass  # ignore jika belum punya atribut

        # jalankan __init__ dengan kwargs yang sudah difilter
        try:
            cls.__init__(det, **filtered_kwargs)
        except TypeError:
            # fallback kalau parameter gak cocok
            cls.__init__(det)
    except Exception as e:
        print(f"[!] Safe instantiation failed for {shortname}: {e}")
        # fallback klasik
        det = cls(**filtered_kwargs)
        det._queue = mon._queue
        try:
            det.output_callback = mon._queue.put
        except Exception:
            pass

    # ✔ Artemon final: pastikan setiap detector punya output_callback
    #if not hasattr(det, "output_callback") or det.output_callback is None:
    #    det.output_callback = mon._queue.put

    # 5️⃣ Pastikan mode realtime diaktifkan jika detector support
    if hasattr(det, "realtime"):
        try:
            det.realtime = True
        except Exception:
            pass

    # 6️⃣ Optional: debug info
    # print(f"[DEBUG] Initialized {shortname} ({cls.__name__}) with _queue={hasattr(det, '_queue')} output_callback={hasattr(det, 'output_callback')}")

    return det
    
def main():    
    print_banner()
    # semua log per-detector masuk ke folder "logs/"
    mon = Monitor(output_callback=print_cb, 
                    logfile="artifact_monitor.log", 
                    max_size_mb=1, # max ukuran sebelum di compress
                    per_detector_logs=True, 
                    per_detector_dir="logs")   
    
    # jalankan menu interaktif
    enabled_set = choose_detectors_interactive()
    print("[*] Enabled detectors (interactive):", enabled_set)

    # register detectors sesuai pilihan
    for shortname in enabled_set:
        if shortname not in DETECTOR_REGISTRY:
            print(f"[!] Detector '{shortname}' not found in DETECTOR_REGISTRY")
            continue        
        try:
            det = init_detector(shortname, mon)
            mon.add_detector(det)
            print(f"[+] Registered '{shortname}' -> {det.__class__.__name__}")
        except Exception as e:
            print(f"[!] Failed to add detector '{shortname}': {e}")
    
    # Start monitoring
    print("Starting monitor... (Ctrl-C to stop)")
    mon.start()

    try:
        while True:
            status = mon.get_detector_status()
            print("[*] Detector threads status:")
            for s in status:
                print(f"  - {s['detector']}: alive={s['thread_alive']} interval={s.get('interval')}s")
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping...")
        mon.stop()
        
if __name__ == "__main__":
    main()    