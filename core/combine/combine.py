import json
import os
from collections import defaultdict

# --- Load JSON file helper ---
def load_json(path):
    if not os.path.exists(path):
        print(f"Skipping missing file: {path}")
        return None
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"Skipping malformed file: {path}")
            return None

# --- File Paths ---
tool_files = {
    "Burp Suite": "vulnerabilities/vulnerabilities_burp.json",
    "ZAP": "vulnerabilities/vulnerabilities_zap.json",
    "Wapiti": "vulnerabilities/vulnerabilities_wapiti.json",
    "Nikto": "vulnerabilities/vulnerabilities_nikto.json",
    "Nuclei": "vulnerabilities/vulnerabilities_nuclei.json",
    "WhatWeb": "vulnerabilities/vulnerabilities_whatweb.json",
    "Wafw00f": "vulnerabilities/vulnerabilities_wafw00f.json"
}

master_file = "vulnerabilities/perfect_list_with_wapiti.json"
master = load_json(master_file)

# --- Reverse Map for Categorization ---
reverse_map = {}
if master:
    for category, tools in master.items():
        for tool, alerts in tools.items():
            for alert in alerts:
                key = alert.lower().strip()
                reverse_map[key] = {"category": category, "tool": tool}

# --- Final Output Structure ---
final_alerts = defaultdict(lambda: {
    "Burp Suite": [],
    "ZAP": [],
    "Wapiti": [],
    "Nikto": [],
    "Nuclei": [],
    "WhatWeb": [],
    "Wafw00f": [],
})

# --- Normalization Logic ---
def normalize_alert(tool, alert):
    normalized = {
        "title": alert.get("name") or alert.get("alert") or alert.get("info", "Unknown Alert")[:60],
        "severity": alert.get("severity") or alert.get("risk") or ("low" if alert.get("level") == 1 else "medium" if alert.get("level") == 2 else "high" if alert.get("level") == 3 else "info"),
        "confidence": alert.get("confidence", "medium"),
        "description": alert.get("description") or alert.get("info"),
        "remediation": alert.get("solution") or alert.get("remediation_background", ""),
        "background": alert.get("issue_background", ""),
        "urls": alert.get("urls") or [alert.get("origin")] if alert.get("origin") else [],
        "paths": alert.get("paths") if alert.get("paths") else ([alert.get("path")] if alert.get("path") else []),
        "parameter": alert.get("parameter", ""),
        "reference": alert.get("reference", ""),
        "curl_command": alert.get("curl_command", ""),
        "http_request": alert.get("http_request", ""),
        "origin": alert.get("origin", ""),
        "type_index": alert.get("type_index", ""),
        "tool": tool
    }
    return normalized

# --- Categorization Helper ---
def categorize_alert(tool_name, alert_name):
    key = alert_name.lower().strip()
    return reverse_map.get(key, {"category": "Uncategorized", "tool": tool_name})

# --- Burp Specific Flatten ---
def flatten_burp(data):
    result = []
    for severity, alerts in data.items():
        for alert in alerts:
            alert["severity"] = severity
            result.append(alert)
    return result

# --- Add Alerts Function ---
def add_alerts(tool, data):
    if not data:
        return

    if tool == "Burp Suite":
        alerts = flatten_burp(data)
        for alert in alerts:
            name = alert.get("name", "")
            info = categorize_alert(tool, name)
            final_alerts[info["category"]][tool].append(normalize_alert(tool, alert))

    elif tool == "ZAP":
        for alert in data:
            name = alert.get("alert", "")
            info = categorize_alert(tool, name)
            final_alerts[info["category"]][tool].append(normalize_alert(tool, alert))

    elif tool == "Wapiti":
        for name, alerts in data.get("vulnerabilities", {}).items():
            info = categorize_alert(tool, name)
            for alert in alerts:
                final_alerts[info["category"]][tool].append(normalize_alert(tool, alert))

    else:
        # Other tools just append as-is into Uncategorized
        for alert in data.get("vulnerabilities", []) if isinstance(data, dict) else data:
            final_alerts["Uncategorized"][tool].append(normalize_alert(tool, alert))

# --- Process All Tools ---
for tool, path in tool_files.items():
    data = load_json(path)
    if data:
        add_alerts(tool, data)

# --- Save Final Output ---
with open("final_alerts.json", "w") as f:
    json.dump(final_alerts, f, indent=4)

print("final_alerts.json has been created with normalized alert format.")
