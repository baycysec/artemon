# recyclebin.py (patched)
# RecycleBinDetector (robust parse_i_file patch)
# - improved UTF-16LE path discovery with multiple offsets
# - tolerant regex-like scan for UTF-16LE drive markers
# - fallbacks for ANSI/UTF-8 style paths
# - preserves original API and return shape

import os
import struct
import re
from datetime import datetime, timezone
from monitor import BaseDetector, now_ts
from logger_util import DetectorLogger  # <-- patch import

# helper convert FILETIME -> ISO UTC string
def filetime_to_iso(filetime_qword):
    try:
        # FILETIME is number of 100-ns intervals since 1601-01-01
        us = int(filetime_qword) / 10  # microseconds
        epoch_diff = 11644473600  # seconds between 1601 and 1970
        ts = (us / 1_000_000) - epoch_diff
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return None

def _is_reasonable_path(p: str) -> bool:
    if not p:
        return False
    # basic sanity: must contain drive letter pattern like C:\
    if ":\\" in p or p.startswith('\\\\'):
        # also require some length
        return len(p) > 3
    return False

def _clean_utf16le_string(s: str) -> str:
    # remove stray nulls and trim
    s = s.replace('\x00', '')
    s = s.strip()
    return s

def parse_i_file(path):
    """
    Robust parser for $I files. Tries multiple offsets to extract:
      - original_path (UTF-16LE or ANSI/UTF-8)
      - original_size (int)
      - deleted_time (ISO str)
      - r_name (paired $R file name)
    Returns dict or None on complete failure.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return None

    if not data or len(data) < 16:
        return None

    original_size = None
    deleted_time_iso = None
    original_path = None
    r_name = None

    # Candidate offsets to try for original_size (commonly 0x08, 0x10, 0x18, 0x20)
    size_offsets = (8, 0x10, 0x18, 0x20, 0x28)
    for off in size_offsets:
        if len(data) >= off + 8:
            try:
                val = struct.unpack_from("<Q", data, off)[0]
                # sanity: sizes >= 0 and < several TB
                if 0 <= val < 10 * 1024**4:
                    original_size = int(val)
                    break
            except Exception:
                continue

    # Candidate offsets for FILETIME (search same candidates)
    ft_offsets = (0x10, 0x08, 0x18, 0x20, 0x28)
    for off in ft_offsets:
        if len(data) >= off + 8:
            try:
                q = struct.unpack_from("<Q", data, off)[0]
                # basic sanity: FILETIME after year 2000 and before far future
                if 116444736000000000 <= q <= 3250368000000000000:
                    deleted_time_iso = filetime_to_iso(q)
                    break
            except Exception:
                continue

    # 1) Try a set of common UTF-16LE offsets and decode outwards until double-null
    utf16_offsets = (0x20, 0x18, 0x1C, 0x28, 0x30, 0x40)
    for off in utf16_offsets:
        if len(data) > off:
            try:
                tail = data[off:]
                # find double-null terminator for UTF-16LE (\x00\x00)
                end_idx = tail.find(b"\x00\x00")
                if end_idx != -1:
                    candidate = tail[:end_idx]
                else:
                    # limit to a reasonable length to avoid huge decodes
                    candidate = tail[:1024]
                # ensure candidate length is even for UTF-16LE decoding (UTF-16 code units = 2 bytes)
                if len(candidate) % 2 == 1:
                    # try to include one more byte to complete the last code unit if available, else drop the dangling byte
                    if off + (end_idx if 'end_idx' in locals() and isinstance(end_idx, int) and end_idx != -1 else 0) + 1 < len(data):
                        candidate = data[off:off + (end_idx if 'end_idx' in locals() and isinstance(end_idx, int) and end_idx != -1 else min(len(candidate), 1024)) + 1]
                    else:
                        candidate = candidate[:-1]
                decoded = candidate.decode("utf-16le", errors="ignore")
                decoded = _clean_utf16le_string(decoded)
                if _is_reasonable_path(decoded):
                    original_path = decoded
                    break
            except Exception:
                continue

    # 2) If not found, brute-force search for UTF-16LE drive markers (A:\ to Z:\)
    if not original_path:
        try:
            for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                marker = f"{drive}:\\".encode("utf-16le")
                idx = data.find(marker)
                if idx != -1:
                    # find following double-null terminator (UTF-16LE)
                    tail = data[idx:]
                    end = tail.find(b"\x00\x00")
                    if end == -1:
                        end = min(len(tail), 2048)
                    chunk = tail[:end]
                    try:
                        decoded = chunk.decode("utf-16le", errors="ignore")
                        decoded = _clean_utf16le_string(decoded)
                        if _is_reasonable_path(decoded):
                            original_path = decoded
                            break
                    except Exception:
                        continue
        except Exception:
            original_path = None

    # 3) Fallback: search for UNC paths in UTF-16LE (\\server\share)
    if not original_path:
        try:
            unc_marker = "\\\\".encode("utf-16le")
            idx = data.find(unc_marker)
            if idx != -1:
                tail = data[idx:]
                end = tail.find(b"\x00\x00")
                if end == -1:
                    end = min(len(tail), 2048)
                chunk = tail[:end]
                decoded = chunk.decode("utf-16le", errors="ignore")
                decoded = _clean_utf16le_string(decoded)
                if _is_reasonable_path(decoded):
                    original_path = decoded
        except Exception:
            pass

    # 4) ANSI / UTF-8 fallback: some $I files may contain OEM/ANSI paths (rare)
    if not original_path:
        try:
            # look for ASCII drive marker like C:\
            ascii_match = re.search(rb"[A-Za-z]:\\[^\x00]{1,512}", data)
            if ascii_match:
                raw = ascii_match.group(0)
                try:
                    decoded = raw.decode("utf-8", errors="ignore")
                except Exception:
                    decoded = raw.decode("latin-1", errors="ignore")
                decoded = decoded.strip('\x00').strip()
                if _is_reasonable_path(decoded):
                    original_path = decoded
        except Exception:
            pass

    # 5) last resort: attempt whole-file UTF-16LE decode and extract printable substring
    if not original_path:
        try:
            txt = data.decode("utf-16le", errors="ignore")
            if txt and len(txt) > 4:
                s = _clean_utf16le_string(txt)
                # crude pick: first occurrence of drive marker
                m = re.search(r"[A-Za-z]:\\[^\n\r]{1,1024}", s)
                if m:
                    candidate = m.group(0)
                    if _is_reasonable_path(candidate):
                        original_path = candidate
        except Exception:
            pass

    # compute expected paired $R name
    base = os.path.basename(path)
    if base and base.startswith("$I"):
        r_name = "$R" + base[2:]

    return {
        "original_path": original_path if original_path else None,
        "original_size": original_size if original_size is not None else None,
        "deleted_time": deleted_time_iso if deleted_time_iso else None,
        "r_name": r_name
    }

class RecycleBinDetector(BaseDetector):
    name = "recyclebin"

    def __init__(self, interval: float = 10.0, scan_all_drives: bool = True):
        """
        interval: poll interval in seconds
        scan_all_drives: if True, look for $Recycle.Bin on all existing drives (C:..Z:)
        """
        super().__init__(interval)
        self.scan_all_drives = bool(scan_all_drives)
        self.rb_paths = self._discover_recycle_bins()  # list of root $Recycle.Bin paths
        self.seen = {}  # map path -> mtime
        self.logger = DetectorLogger(self.name)     

    def _discover_recycle_bins(self):
        roots = []
        drives = []
        if self.scan_all_drives:
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                d = f"{letter}:" + os.sep
                if os.path.exists(d):
                    drives.append(d)
        else:
            sysdrive = os.path.splitdrive(os.environ.get("SYSTEMDRIVE", "C:"))[0] + os.sep
            drives = [sysdrive]

        for d in drives:
            rb = os.path.join(d, "$Recycle.Bin")
            if os.path.exists(rb) and os.path.isdir(rb):
                roots.append(rb)
        return roots

    def poll(self):
        events = []
        # refresh recycle bin dirs occasionally in case new volumes mounted
        current_roots = self._discover_recycle_bins()
        if set(current_roots) != set(self.rb_paths):
            self.rb_paths = current_roots

        for rb in list(self.rb_paths):
            # each user SID subfolder
            try:
                for sid in os.listdir(rb):
                    sid_path = os.path.join(rb, sid)
                    if not os.path.isdir(sid_path):
                        continue
                    # list files in this SID folder
                    try:
                        for fname in os.listdir(sid_path):
                            # we're interested in $I* files (metadata)
                            if not fname.startswith("$I"):
                                continue
                            full = os.path.join(sid_path, fname)
                            try:
                                mtime = os.path.getmtime(full)
                            except Exception:
                                mtime = None
                            prev = self.seen.get(full)
                            if prev and mtime == prev:
                                continue

                            # parse $I file (robust)
                            info = parse_i_file(full)

                            # build minimal event always (so parsing failure doesn't drop detection)
                            event = {
                                "type": "recyclebin",
                                "i_path": full,
                                "ts": now_ts()
                            }                
                            self.logger.info({"detector": self.name, "event": event})

                            if info:
                                # attach parser results if present
                                event["original_path"] = info.get("original_path")
                                event["original_size"] = info.get("original_size")
                                event["deleted_time"] = info.get("deleted_time")
                                # attempt to resolve paired $R path if present
                                r_path = None
                                r_name = info.get("r_name")
                                if r_name:
                                    possible_r = os.path.join(sid_path, r_name)
                                    if os.path.exists(possible_r):
                                        r_path = possible_r
                                event["r_path"] = r_path

                            events.append(event)
                            # mark seen after creating event
                            self.seen[full] = mtime
                    except Exception:
                        # continue scanning other SID folders even if one fails
                        continue
            except Exception:
                continue

        return events
