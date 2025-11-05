# detectors/schtask.py (patched hybrid + eventlog integration)
import subprocess, re, xml.etree.ElementTree as ET
from monitor import BaseDetector, now_ts
from datetime import datetime
import os
from logger_util import DetectorLogger  # <-- patch import

def safe_run(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return out.decode(errors="ignore")
    except:
        return ""
        
def get_task_action(task_name):
    """Resolve scheduled task action (command + args)."""
    tname = task_name.lstrip("\\")
    # coba XML
    try:
        out = subprocess.check_output(
            ["schtasks", "/Query", "/TN", tname, "/XML"],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        if out.strip():
            try:
                root = ET.fromstring(out)
                cmd = None
                args = ""
                for exec_el in root.findall(".//Exec"):
                    c = exec_el.find("Command")
                    a = exec_el.find("Arguments")
                    if c is not None and c.text:
                        cmd = c.text.strip()
                    if a is not None and a.text:
                        args = a.text.strip()
                    if cmd:
                        return {"command": cmd, "arguments": args}
            except ET.ParseError:
                pass
    except Exception:
        pass

    # fallback: verbose list
    try:
        out = subprocess.check_output(
            ["schtasks", "/Query", "/TN", tname, "/V", "/FO", "LIST"],
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        cmd, args = None, ""
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("task to run:"):
                val = line.split(":", 1)[1].strip().strip('"')
                parts = val.split()
                if parts:
                    cmd = parts[0]
                    args = " ".join(parts[1:]) if len(parts) > 1 else ""
                    return {"command": cmd, "arguments": args}
            if line.lower().startswith("command:"):
                cmd = line.split(":", 1)[1].strip().strip('"')
            if line.lower().startswith("arguments:"):
                args = line.split(":", 1)[1].strip().strip('"')
        if cmd:
            return {"command": cmd, "arguments": args}
    except Exception:
        pass

    return {"command": None, "arguments": None}

def _normalize_task_name(task_name: str) -> str:
    """Ensure task name acceptable for schtasks queries (remove leading/trailing whitespace)."""
    return task_name.strip().lstrip("\\")

def _text_of(elem):
    if elem is None:
        return None
    if elem.text is None:
        return None
    return elem.text.strip()

def _strip_ns(tag: str) -> str:
    """Remove namespace portion if present: '{...}Tag' -> 'Tag'"""
    if tag is None:
        return ""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag

def _parse_task_xml(xml_text: str) -> dict:
    """
    Parse Task XML and extract relevant fields.
    Return dict with keys: command, arguments, triggers (list), principal (user), runlevel,
    author, enabled (bool), last_run_time, next_run_time, last_result, status.
    Many fields may be None if not present.
    """
    details = {
        "command": None,
        "arguments": None,
        "triggers": [],
        "principal": None,
        "runlevel": None,
        "author": None,
        "enabled": None,
        "last_run_time": None,
        "next_run_time": None,
        "last_result": None,
        "status": None
    }
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return details

    # registration info / author
    for reg in root.iter():
        tag = _strip_ns(reg.tag)
        if tag.lower() == "registrationinfo":
            author_el = reg.find(".//{*}Author")
            if author_el is not None and author_el.text:
                details["author"] = author_el.text.strip()
            break

    # Principals
    for princ in root.iter():
        tag = _strip_ns(princ.tag)
        if tag.lower() == "principals":
            # take first Principal
            p = princ.find(".//{*}Principal")
            if p is not None:
                uid = p.find(".//{*}UserId")
                rl = p.find(".//{*}RunLevel")
                if uid is not None and uid.text:
                    details["principal"] = uid.text.strip()
                if rl is not None and rl.text:
                    details["runlevel"] = rl.text.strip()
            break

    # Triggers: collect types present
    triggers = []
    for tnode in root.findall(".//"):
        ttag = _strip_ns(tnode.tag).lower()
        # trigger types in Task Schema include: Logon, TimeTrigger, Boot, EventTrigger, Daily, Weekly, etc.
        if ttag.endswith("trigger") or ttag in ("logon", "boot", "time", "onstart", "onlogon"):
            # take element name as trigger type
            triggers.append(_strip_ns(tnode.tag))
    if triggers:
        details["triggers"] = triggers

    # Actions -> find Exec elements
    # Prefer first Exec found
    command = None
    arguments = None
    for node in root.findall(".//"):
        if _strip_ns(node.tag).lower() == "exec":
            cmd_el = node.find(".//{*}Command")
            arg_el = node.find(".//{*}Arguments")
            if cmd_el is not None and cmd_el.text:
                command = cmd_el.text.strip()
            if arg_el is not None and arg_el.text:
                arguments = arg_el.text.strip()
            if command:
                break
    details["command"] = command
    details["arguments"] = arguments or ""

    # Settings / Status fields - not always in XML; attempt to find LastRunTime / NextRunTime / LastTaskResult
    # These are often available via schtasks /V /FO LIST instead; leave None here.
    return details

def _parse_task_list_verbose(text: str) -> dict:
    """
    Parse the verbose LIST output of schtasks for a single task.
    Extract fields with best-effort: Task To Run, Author, Run As User, Status, Last Run Time, Next Run Time, Last Result.
    """
    details = {
        "command": None,
        "arguments": None,
        "triggers": [],
        "principal": None,
        "runlevel": None,
        "author": None,
        "enabled": None,
        "last_run_time": None,
        "next_run_time": None,
        "last_result": None,
        "status": None
    }

    # Normalize lines
    lines = []
    for raw in text.splitlines():
        if not raw:
            continue
        # Some lines may be 'Name:    value' or 'Name: value' depending on locales
        lines.append(raw.rstrip())

    # Helper: find line by key (case-insensitive start) and return value
    def find_key_start(prefixes):
        for ln in lines:
            l = ln.strip()
            for pref in prefixes:
                if l.lower().startswith(pref.lower()):
                    parts = l.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip().strip('"')
                    else:
                        return ""
        return None

    # Try common keys (English); if localised OS used, XML route is preferred
    task_to_run = find_key_start(["task to run", "task run", "task to run:"])
    if task_to_run:
        # split into command and args
        parts = task_to_run.split()
        if parts:
            details["command"] = parts[0].strip('"')
            details["arguments"] = " ".join(parts[1:]) if len(parts) > 1 else ""

    author = find_key_start(["author", "registered by", "author:"])
    if author:
        details["author"] = author

    run_as = find_key_start(["run as user", "run as user:", "run as:"])
    if run_as:
        details["principal"] = run_as

    status = find_key_start(["status", "state"])
    if status:
        details["status"] = status

    last_run = find_key_start(["last run time", "last run time:"])
    if last_run:
        details["last_run_time"] = last_run
    next_run = find_key_start(["next run time", "next run time:"])
    if next_run:
        details["next_run_time"] = next_run

    last_result = find_key_start(["last result", "last run result"])
    if last_result:
        details["last_result"] = last_result

    # Enabled/Disabled sometimes present as "Scheduled Task State: Enabled" or "Enabled: True"
    enabled_val = find_key_start(["enabled", "scheduled task state"])
    if enabled_val:
        details["enabled"] = ("enable" in enabled_val.lower()) or (enabled_val.lower() in ("true", "yes"))

    # return best-effort details
    return details

def get_task_details(task_name: str) -> dict:
    """
    Return a details dict for a given scheduled task name.
    Strategy:
      1) Try XML via 'schtasks /Query /TN <name> /XML' and parse structured data.
      2) Fallback to 'schtasks /Query /TN <name> /V /FO LIST' and parse human-readable fields.
    """
    t = _normalize_task_name(task_name)
    details = {
        "command": None,
        "arguments": None,
        "triggers": [],
        "principal": None,
        "runlevel": None,
        "author": None,
        "enabled": None,
        "last_run_time": None,
        "next_run_time": None,
        "last_result": None,
        "status": None
    }

    # Try XML
    try:
        out = safe_run(["schtasks", "/Query", "/TN", t, "/XML"])
        if out and out.strip():
            parsed = _parse_task_xml(out)
            # merge parsed into details (prefer XML values)
            for k, v in parsed.items():
                if v is not None:
                    details[k] = v
            # XML doesn't include last run/next run in many cases; try verbose for those
    except Exception:
        out = ""

    # Try verbose list to fill remaining fields (or as fallback)
    try:
        verbose = safe_run(["schtasks", "/Query", "/TN", t, "/V", "/FO", "LIST"])
        if verbose and verbose.strip():
            parsed_v = _parse_task_list_verbose(verbose)
            for k, v in parsed_v.items():
                # if detail missing from XML, fill from verbose; for command prefer XML but use verbose if empty
                if details.get(k) in (None, "", []) and v not in (None, "", []):
                    details[k] = v
            # sometimes command present in verbose even if XML parsed none
            if (not details.get("command")) and parsed_v.get("command"):
                details["command"] = parsed_v.get("command")
                details["arguments"] = parsed_v.get("arguments")
    except Exception:
        pass

    return details

def _details_diff(old: dict, new: dict) -> dict:
    """Return dict with keys changed between old and new (old_value, new_value)."""
    diff = {}
    keys = set(old.keys()) | set(new.keys())
    for k in keys:
        o = old.get(k)
        n = new.get(k)
        if o != n:
            diff[k] = {"old": o, "new": n}
    return diff

class ScheduledTaskDetector(BaseDetector):
    name = "scheduled_task"

    def __init__(self, interval: float = 30.0):
        super().__init__(interval)
        #self.prev_tasks = set()
        # prev_tasks maps task_name -> details dict (for change detection)
        self.prev_tasks = {}     
        self.logger = DetectorLogger(self.name)

    def _read_event_triggers(self, path="logs/_event_signals/schtask_trigger.txt"):
        """Read new TaskScheduler triggers from eventlog detector output."""
        if not os.path.exists(path):
            return []
        events = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if not hasattr(self, "_last_trigger_count"):
                self._last_trigger_count = 0
            new_lines = lines[self._last_trigger_count:]
            self._last_trigger_count = len(lines)
            for line in new_lines:
                parts = line.strip().split("|")
                if len(parts) >= 3:
                    ts, eid, tname = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    events.append((eid, tname))
        except Exception:
            pass
        return events

    def _enumerate_tasks(self) -> set:
        """Return set of task names using schtasks /query /fo LIST /v (fast)."""
        out = safe_run(["schtasks", "/query", "/fo", "LIST", "/v"])
        tasks = set()
        for line in out.splitlines():
            try:
                if line.strip().lower().startswith("taskname:"):
                    tname = line.split(":", 1)[1].strip()
                    tasks.add(tname)
            except Exception:
                continue
        return tasks
    
    def poll(self):
        events = []
        # --- NEW: eventlog-trigger integration ---
        trigger_events = self._read_event_triggers()
        if trigger_events:
            for eid, tname in trigger_events:
                details = get_task_details(tname)
                event = {
                    "type": "task_event_triggered",
                    "source_eventid": eid,
                    "task": tname,
                    "details": details,
                    "ts": now_ts()
                }                
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)
            # jika trigger event terdeteksi, langsung return (tanpa full rescan)
            return events

        # --- Check for eventlog-triggered tasks ---
        trigger_path = os.path.join("logs", "_event_signals", "schtask_trigger.txt")
        if os.path.exists(trigger_path):
            try:
                with open(trigger_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                open(trigger_path, "w").close()  # clear after read

                for line in lines:
                    parts = line.strip().split("|")
                    if len(parts) < 3:
                        continue
                    ts, event_id, taskname = [p.strip() for p in parts[:3]]
                    event_id = int(event_id)

                    event_type_map = {
                        106: "task_created_realtime",
                        110: "task_executed_realtime",
                        140: "task_modified_realtime",
                        141: "task_deleted_realtime",
                        #111: "task_completed_realtime"
                    }
                    etype = event_type_map.get(event_id, "task_event_triggered")

                    # handle delete first
                    if event_id == 141:
                        event = {
                            "type": etype,
                            "source_eventid": str(event_id),
                            "task": taskname,
                            "ts": now_ts()
                        }                
                        self.logger.info({"detector": self.name, "event": event})
                        events.append(event)                        

                        if taskname in self.prev_tasks:
                            del self.prev_tasks[taskname]
                        continue
                        
                    # for create/update, fetch details
                    if event_id in (106, 110, 140):
                        details = get_task_details(taskname)
                        event = {
                            "type": etype,
                            "source_eventid": str(event_id),
                            "task": taskname,
                            "details": details,
                            "ts": now_ts()
                        }                
                        self.logger.info({"detector": self.name, "event": event})
                        events.append(event)                        
                        
                        self.prev_tasks[taskname] = details

            except Exception as e:
                events.append({
                    "type": "error",
                    "msg": f"Failed reading trigger file: {e}",
                    "ts": now_ts()
                })

        # --- fallback ke full scan jika tidak ada trigger baru ---        
        current = self._enumerate_tasks()

        # Detect new tasks and modified tasks
        for t in current:
            if t not in self.prev_tasks:
                # New task -> collect details
                details = get_task_details(t)
                event = {
                    "type": "task_created",
                    "task": t,
                    "details": details,
                    "ts": now_ts()
                }                
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                        
            else:
                # existing task -> compare details to detect modifications
                old_details = self.prev_tasks.get(t) or {}
                # For efficiency: only fetch full details if something likely changed.
                # We will fetch details and diff fully.
                new_details = get_task_details(t)
                diff = _details_diff(old_details, new_details)
                if diff:
                    event = {
                        "type": "task_modified",
                        "task": t,
                        "old": old_details,
                        "new": new_details,
                        "diff": diff,
                        "ts": now_ts()
                    }                
                    self.logger.info({"detector": self.name, "event": event})
                    events.append(event)                        

        # Detect removed tasks
        for t in list(self.prev_tasks.keys()):
            if t not in current:
                event = {
                    "type": "task_removed",
                    "task": t,
                    "old_details": self.prev_tasks.get(t),
                    "ts": now_ts()
                }                
                self.logger.info({"detector": self.name, "event": event})
                events.append(event)                        

        # Update prev_tasks mapping with current details for next poll
        # Build new mapping: fetch details for all current tasks but try to reuse existing where possible
        new_prev = {}
        for t in current:
            if t in self.prev_tasks:
                # keep previously stored details if we detected no change (avoid re-query)
                new_prev[t] = self.prev_tasks[t]
            else:
                # store details we already fetched above when creating event, otherwise fetch
                # attempt to re-use last details from created event in events list
                created_entry = next((e for e in events if e.get("type") == "task_created" and e.get("task") == t), None)
                modified_entry = next((e for e in events if e.get("type") == "task_modified" and e.get("task") == t), None)
                if created_entry:
                    new_prev[t] = created_entry.get("details") or {}
                elif modified_entry:
                    new_prev[t] = modified_entry.get("new") or {}
                else:
                    # final fallback: fetch details now
                    new_prev[t] = get_task_details(t) or {}
        self.prev_tasks = new_prev

        return events
