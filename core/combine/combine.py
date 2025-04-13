import json
from collections import defaultdict

# --- Load JSON files ---
def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

# FILE PATHS — change as needed
master_file = "vulnerabilities/perfect_list_with_wapiti.json"
burp_file = "vulnerabilities/vulnerabilities_burp.json"
zap_file = "vulnerabilities/vulnerabilities_zap.json"
wapiti_file = "vulnerabilities/vulnerabilities_wapiti.json"

master = load_json(master_file)
burp_data = load_json(burp_file)
zap_data = load_json(zap_file)
wapiti_data = load_json(wapiti_file)

# --- Reverse map: alert name → category/tool ---
reverse_map = {}
for category, tools in master.items():
    for tool, alerts in tools.items():
        for alert in alerts:
            key = alert.lower().strip()
            reverse_map[key] = {"category": category, "tool": tool}

# --- Output structure ---
final_alerts = defaultdict(lambda: {"Burp Suite": [], "ZAP": [], "Wapiti": [], "Uncategorized": []})

# --- BURP ---
def flatten_burp(burp):
    result = []
    for severity, alerts in burp.items():
        for alert in alerts:
            alert["severity"] = severity
            result.append(alert)
    return result

def add_burp_alerts(burp_parsed):
    flat = flatten_burp(burp_parsed)
    for alert in flat:
        name = alert.get("name", "").lower().strip()
        info = reverse_map.get(name)
        if info and info["tool"] == "Burp Suite":
            final_alerts[info["category"]]["Burp Suite"].append(alert)
        else:
            final_alerts["Uncategorized"]["Uncategorized"].append(alert)

# --- ZAP ---
def add_zap_alerts(zap_parsed):
    for alert in zap_parsed:
        name = alert.get("alert", "").lower().strip()
        info = reverse_map.get(name)
        if info and info["tool"] == "ZAP":
            final_alerts[info["category"]]["ZAP"].append(alert)
        else:
            final_alerts["Uncategorized"]["Uncategorized"].append(alert)

# --- WAPITI ---
def add_wapiti_alerts(wapiti_parsed):
    for name, alerts in wapiti_parsed.get("vulnerabilities", {}).items():
        norm_name = name.lower().strip()
        info = reverse_map.get(norm_name)
        for alert in alerts:
            if info and info["tool"] == "Wapiti":
                final_alerts[info["category"]]["Wapiti"].append(alert)
            else:
                final_alerts["Uncategorized"]["Uncategorized"].append(alert)

# --- Add everything to final ---
add_burp_alerts(burp_data)
add_zap_alerts(zap_data)
add_wapiti_alerts(wapiti_data)

# --- Save output ---
with open("final_alerts.json", "w") as f:
    json.dump(final_alerts, f, indent=4)

print("✅ final_alerts.json has been created.")
