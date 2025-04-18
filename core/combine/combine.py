import json
import os
from collections import defaultdict, OrderedDict # Import OrderedDict for controlled output order
import logging

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# --- Load JSON file helper ---
def load_json(path):
    """Loads a JSON file, returns None if missing or invalid."""
    if not os.path.exists(path):
        logging.warning(f"Skipping missing file: {path}")
        return None
    try:
        # Ensure file is not empty before trying to load
        if os.path.getsize(path) == 0:
            logging.warning(f"Skipping empty file: {path}")
            return None
        with open(path, "r", encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Skipping malformed file: {path} - Error: {e}")
        return None
    except Exception as e:
        logging.error(f"Error reading file {path}: {e}")
        return None

# --- File Paths ---
# Ensure these paths are relative to where combine.py is executed
tool_files = {
    "Burp Suite": "vulnerabilities/vulnerabilities_burp.json",
    "ZAP": "vulnerabilities/vulnerabilities_zap.json",
    "Wapiti": "vulnerabilities/vulnerabilities_wapiti.json",
    "Nikto": "vulnerabilities/vulnerabilities_nikto.json",
    "Nuclei": "vulnerabilities/vulnerabilities_nuclei.json",
    "WhatWeb": "vulnerabilities/vulnerabilities_whatweb.json",
    "Wafw00f": "vulnerabilities/vulnerabilities_wafw00f.json"
}

master_file = "perfect_list_with_wapiti.json" # Ensure this path is correct
master = load_json(master_file)

# --- Reverse Map for Categorization ---
reverse_map = {}
if master:
    for category, tools in master.items():
        if isinstance(tools, dict):
            for tool, alerts in tools.items():
                if isinstance(alerts, list):
                    for alert_name in alerts:
                        if isinstance(alert_name, str):
                            key = alert_name.lower().strip()
                            if key not in reverse_map:
                                reverse_map[key] = {"category": category, "tool": tool}
                        else:
                            logging.warning(f"Non-string alert name found in master file: {alert_name} under {category}/{tool}")
                else:
                    logging.warning(f"Alerts entry for {category}/{tool} is not a list.")
        else:
            logging.warning(f"Tools entry for category {category} is not a dictionary.")
else:
    logging.error(f"Master file '{master_file}' could not be loaded or is empty. Categorization will be limited.")

# --- Intermediate Output Structure (unordered) ---
# Using defaultdict temporarily during processing
intermediate_alerts = defaultdict(dict)

# Function to ensure category and tool keys exist in the intermediate dict
def ensure_intermediate_keys(category, tool):
    if tool not in intermediate_alerts[category]:
        intermediate_alerts[category][tool] = []

# --- Normalization Logic (keep from previous version) ---
def normalize_alert(tool, alert):
    """Creates a standardized dictionary for a vulnerability alert."""
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "med": "medium", "low": "low", "info": "info", "information": "info"}
    raw_severity = str(alert.get("severity") or alert.get("risk") or "info").lower()
    normalized_severity = severity_map.get(raw_severity, "info")

    urls = alert.get("urls", [])
    if isinstance(urls, str): urls = [urls]
    if not urls and alert.get("url"): urls = [alert.get("url")]
    if not urls and alert.get("origin"): urls = [alert.get("origin")]

    paths = alert.get("paths", [])
    if isinstance(paths, str): paths = [paths]
    if not paths and alert.get("path"): paths = [alert.get("path")]

    normalized = {
        "title": str(alert.get("name", "") or alert.get("alert", "") or alert.get("title", "") or alert.get("info", "Unknown Alert"))[:150],
        "severity": normalized_severity,
        "confidence": str(alert.get("confidence", "medium")),
        "description": str(alert.get("description", "") or alert.get("info", "")),
        "remediation": str(alert.get("solution", "") or alert.get("remediation", "") or alert.get("remediation_background", "")),
        "background": str(alert.get("issue_background", "") or alert.get("background", "")),
        "urls": [str(u) for u in urls if u],
        "paths": [str(p) for p in paths if p],
        "parameter": str(alert.get("parameter", "")),
        "reference": str(alert.get("reference", "")),
        "curl_command": str(alert.get("curl_command", "")),
        "http_request": str(alert.get("http_request", "")),
        "tool": tool
    }
    return {k: v for k, v in normalized.items() if v or isinstance(v, list) and v}

# --- Categorization Helper (keep from previous version) ---
def categorize_alert(tool_name, alert_title):
    """Finds category for an alert title using the reverse_map."""
    if not alert_title or not isinstance(alert_title, str):
                return {"category": "Uncategorized", "tool": tool_name}
    key = alert_title.lower().strip()
    return reverse_map.get(key, {"category": "Uncategorized", "tool": tool_name})

# --- Burp Specific Flatten (keep from previous version) ---
def flatten_burp(data):
    """Flattens Burp data assuming {severity: [alerts...]} structure."""
    result = []
    if not isinstance(data, dict):
        logging.warning("Burp data is not a dictionary, cannot flatten.")
        return result
    for severity, alerts in data.items():
        if isinstance(alerts, list):
            for alert in alerts:
                if isinstance(alert, dict):
                    alert["severity"] = severity
                    result.append(alert)
    return result

# --- Add Alerts Function (Modified for WhatWeb) ---
def add_alerts(tool, data):
    """Processes and adds alerts from a tool's data to the intermediate_alerts structure."""
    if not data:
        logging.warning(f"No data loaded for tool: {tool}")
        return

    logging.info(f"Processing data for tool: {tool}")

    if tool == "Burp Suite":
        alerts_list = flatten_burp(data)
        for alert in alerts_list:
            name = alert.get("name", "Unknown Burp Alert")
            info = categorize_alert(tool, name)
            category = info["category"]
            ensure_intermediate_keys(category, tool)
            intermediate_alerts[category][tool].append(normalize_alert(tool, alert))

    elif tool == "ZAP":
        if isinstance(data, list):
            for alert in data:
                if isinstance(alert, dict):
                    name = alert.get("alert", "Unknown ZAP Alert")
                    info = categorize_alert(tool, name)
                    category = info["category"]
                    ensure_intermediate_keys(category, tool)
                    intermediate_alerts[category][tool].append(normalize_alert(tool, alert))
                else:
                    logging.warning(f"Skipping non-dictionary item in ZAP data: {alert}")
        else:
            logging.warning(f"ZAP data is not a list: {type(data)}")

    elif tool == "Wapiti":
        if isinstance(data, dict) and "vulnerabilities" in data and isinstance(data["vulnerabilities"], dict):
            for name, alerts_list in data["vulnerabilities"].items():
                if isinstance(alerts_list, list):
                    info = categorize_alert(tool, name)
                    category = info["category"]
                    ensure_intermediate_keys(category, tool)
                    for alert in alerts_list:
                        if isinstance(alert, dict):
                            if "name" not in alert and "alert" not in alert:
                                alert["name"] = name
                            intermediate_alerts[category][tool].append(normalize_alert(tool, alert))
                        else:
                            logging.warning(f"Skipping non-dictionary alert in Wapiti list for '{name}': {alert}")
                else:
                    logging.warning(f"Alerts list for Wapiti vulnerability '{name}' is not a list.")
        else:
            logging.warning(f"Wapiti data format unexpected: {type(data)}")

    elif tool == "Wafw00f":
        if isinstance(data, dict) and "firewalls_detected" in data:
            detected_list = data["firewalls_detected"]
            if isinstance(detected_list, list) and detected_list:
                category = "Firewall Detected" # Specific category
                ensure_intermediate_keys(category, tool)
                logging.info(f"Found {len(detected_list)} firewall detections from Wafw00f.")
                for fw_info in detected_list:
                    if isinstance(fw_info, dict):
                        waf_entry = {
                            "title": f"Detected: {fw_info.get('firewall', 'Unknown Firewall')}",
                            "severity": "info",
                            "description": f"Manufacturer: {fw_info.get('manufacturer', 'Unknown')}. Detected on URL: {fw_info.get('url', 'N/A')}",
                            "tool": tool
                        }
                        intermediate_alerts[category][tool].append(waf_entry)
                    else:
                        logging.warning(f"Skipping non-dictionary item in Wafw00f detected_list: {fw_info}")
            else:
                logging.info("Wafw00f ran but detected no firewalls.")
        else:
            logging.warning(f"Wafw00f data format unexpected or missing 'firewalls_detected': {type(data)}")

    # --- NEW: Handling for WhatWeb ---
    elif tool == "WhatWeb":
        # Expecting {"target_url": ..., "http_status": ..., "technologies": {name: [details...]}}
        if isinstance(data, dict) and "technologies" in data:
            tech_dict = data.get("technologies", {})
            if tech_dict: # Check if technologies were actually found
                category = "Technologies Detected" # Specific category
                ensure_intermediate_keys(category, tool)
                logging.info(f"Found {len(tech_dict)} technology types from WhatWeb.")
                for tech_name, details_list in tech_dict.items():
                    description = ""
                    title = f"WhatWeb: {tech_name} Detected"
                    if isinstance(details_list, list):
                        for details in details_list:
                            if isinstance(details, dict) and "string" in details:
                                if isinstance(details["string"], list):
                                    description = ", ".join(details["string"])
                                else:
                                    description = details["string"]
                                break # Use the first "string" found
                    elif isinstance(details_list, dict) and "string" in details_list:
                        if isinstance(details_list["string"], list):
                            description = ", ".join(details_list["string"])
                        else:
                            description = details_list["string"]

                    alert = {
                        "title": title,
                        "severity": "info", # Technology detection is informational
                        "description": f"Target: {data.get('target_url', 'N/A')} (Status: {data.get('http_status', 'N/A')}). {description}",
                        "tool": tool
                    }
                    intermediate_alerts[category][tool].append(normalize_alert(tool, alert))
            else:
                logging.info(f"WhatWeb ran but detected no technologies.")
        else:
            logging.warning(f"WhatWeb data format unexpected or missing 'technologies': {type(data)}")

    # --- Generic/Else block for other tools ---
    else:
        logging.info(f"Processing tool '{tool}' with generic vulnerability handler.")
        category = "Uncategorized" # Default category
        ensure_intermediate_keys(category, tool)

        alerts_to_add = []
        # Assuming tools like Nuclei or a potential Nikto parser output a LIST of alerts
        if isinstance(data, list):
            alerts_to_add = [normalize_alert(tool, alert) for alert in data if isinstance(alert, dict)]
            if not alerts_to_add and data: # If it was a list but contained no valid dicts
                logging.warning(f"Data for '{tool}' was a list but contained no parsable alert dictionaries.")
                # Add a placeholder indicating raw data presence if needed
                # alerts_to_add.append({"title": f"Raw data present for tool {tool}", "details": str(data)[:500], "tool": tool})
        # Handle dictionary format if it's simple {vuln_name: [details]} - less common now
        elif isinstance(data, dict) and "vulnerabilities" in data and isinstance(data.get("vulnerabilities"), dict):
            logging.warning(f"Tool '{tool}' has dict format - processing values as alert lists.")
            for name, alerts_list in data["vulnerabilities"].items():
                if isinstance(alerts_list, list):
                    for alert in alerts_list:
                        if isinstance(alert, dict):
                            if "name" not in alert and "alert" not in alert:
                                alert["name"] = name # Try to add name from key
                            alerts_to_add.append(normalize_alert(tool, alert))
                else:
                    logging.warning(f"Alert list for '{name}' in '{tool}' data is not a list.")
        else:
            logging.warning(f"Data format for '{tool}' not recognized by generic handler: {type(data)}. Storing placeholder.")
            alerts_to_add.append({"title": f"Unprocessed data present for tool {tool}", "details": str(data)[:500], "tool": tool})

        if alerts_to_add:
            intermediate_alerts[category][tool].extend(alerts_to_add)
        else:
            logging.info(f"No processable alerts found for tool '{tool}' with generic handler.")


# --- Process All Tools ---
logging.info("Starting to process tool outputs...")
for tool, path in tool_files.items():
    logging.info(f"Loading data for: {tool} from {path}")
    data = load_json(path)
    if data is not None:
        add_alerts(tool, data)
    else:
        logging.warning(f"Skipped processing for {tool} due to missing or invalid file.")

# --- Create Final Ordered Output ---
final_alerts_ordered = OrderedDict()

# Add Firewall category first if it exists
if "Firewall Detected" in intermediate_alerts:
    final_alerts_ordered["Firewall Detected"] = intermediate_alerts["Firewall Detected"]
    logging.info("Added 'Firewall Detected' category to final output.")

# Add Technologies category second if it exists
if "Technologies Detected" in intermediate_alerts:
    final_alerts_ordered["Technologies Detected"] = intermediate_alerts["Technologies Detected"]
    logging.info("Added 'Technologies Detected' category to final output.")

# Add remaining categories (can sort them alphabetically if desired)
other_categories = sorted([cat for cat in intermediate_alerts if cat not in ["Firewall Detected", "Technologies Detected"]])

for category in other_categories:
    final_alerts_ordered[category] = intermediate_alerts[category]
    logging.info(f"Added '{category}' category to final output.")


# --- Save Final Output ---
output_filename = "final_alerts.json"
logging.info(f"Saving combined and ordered results to {output_filename}")
try:
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_filename, "w", encoding='utf-8') as f:
        # Use the ordered dictionary for saving
        json.dump(final_alerts_ordered, f, indent=4)
    logging.info(f"{output_filename} has been created successfully.")
except Exception as e:
    logging.exception(f"Error saving final output to {output_filename}: {e}")