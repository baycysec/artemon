import os
import time
import threading
import logging

# Lokasi Jumplist (AutomaticDestinations)
JUMPLIST_PATH = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations")

def start_jumplist_detector(log_dir="logs", interval=5):
    """
    Realtime Jumplist Detector (simple polling watcher).
    Cek perubahan isi folder Jumplist setiap interval detik.
    """
    logger = logging.getLogger("JumplistDetector")
    logger.setLevel(logging.INFO)

    # Logging ke file khusus detector
    log_file = os.path.join(log_dir, "jumplist_detector.log")
    fh = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    def monitor():
        logger.info("[*] Jumplist detector started")
        prev_files = set()

        while True:
            try:
                if not os.path.exists(JUMPLIST_PATH):
                    logger.warning(f"Path not found: {JUMPLIST_PATH}")
                    time.sleep(interval)
                    continue

                current_files = set(os.listdir(JUMPLIST_PATH))

                # File baru
                new_files = current_files - prev_files
                for f in new_files:
                    logger.info(f"[+] New jumplist file detected: {f}")

                # File hilang
                removed_files = prev_files - current_files
                for f in removed_files:
                    logger.info(f"[-] Jumplist file removed: {f}")

                prev_files = current_files

            except Exception as e:
                logger.error(f"Error: {e}")

            time.sleep(interval)

    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    return t
