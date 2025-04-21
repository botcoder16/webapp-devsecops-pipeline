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

# --- Reverse Map for Categorization (excluding Nuclei) ---
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
intermediate_alerts = defaultdict(lambda: defaultdict(list)) # Simplified initialization

# Function to ensure category and tool keys exist (handled by defaultdict now)
# def ensure_intermediate_keys(category, tool):
#     if tool not in intermediate_alerts[category]:
#         intermediate_alerts[category][tool] = [] # No longer needed with defaultdict

# --- Normalization Logic (updated slightly for flexibility) ---
def normalize_alert(tool, alert):
    """Creates a standardized dictionary for a vulnerability alert."""
    severity_map = {"critical": "critical", "high": "high", "medium": "medium", "med": "medium", "low": "low", "info": "info", "information": "info", "unknown": "info"} # Added unknown
    raw_severity = str(alert.get("severity") or alert.get("risk") or "info").lower()
    normalized_severity = severity_map.get(raw_severity, "info")

    urls = alert.get("urls", [])
    if isinstance(urls, str): urls = [urls]
    # Updated logic: prioritize 'matched-at', then 'url', then 'origin'
    if not urls and alert.get("matched-at"): urls = [alert.get("matched-at")]
    if not urls and alert.get("url"): urls = [alert.get("url")]
    if not urls and alert.get("origin"): urls = [alert.get("origin")] # Keep origin as fallback

    paths = alert.get("paths", [])
    if isinstance(paths, str): paths = [paths]
    if not paths and alert.get("path"): paths = [alert.get("path")]

    # Enhanced title extraction: prioritize 'title', then 'name', then 'alert', etc.
    title_candidates = [
        alert.get("title"),
        alert.get("name"),
        alert.get("alert"),
        alert.get("info", {}).get("name"), # Check nested info.name specifically
        "Unknown Alert" # Default
    ]
    normalized_title = next((t for t in title_candidates if t), "Unknown Alert")[:150] # Take first non-empty

    # Enhanced description extraction
    description_candidates = [
        alert.get("description"),
        alert.get("info", {}).get("description"), # Check nested info.description
        alert.get("info") if isinstance(alert.get("info"), str) else "" # Handle info being a string
    ]
    normalized_description = next((d for d in description_candidates if d), "")

    # Enhanced remediation extraction
    remediation_candidates = [
        alert.get("remediation"),
        alert.get("solution"),
        alert.get("remediation_background"),
        alert.get("info", {}).get("remediation") # Check nested info.remediation
    ]
    normalized_remediation = next((r for r in remediation_candidates if r), "")

    # Enhanced background extraction
    background_candidates = [
        alert.get("background"),
        alert.get("issue_background"),
        alert.get("info", {}).get("background") # Check nested info.background
    ]
    normalized_background = next((b for b in background_candidates if b), "")

    # Enhanced reference extraction
    reference_candidates = [
        alert.get("reference"),
        alert.get("template-url"), # For Nuclei
        alert.get("info", {}).get("reference") # Check nested info.reference
    ]
    normalized_reference = next((r for r in reference_candidates if r), "")

    # Parameter extraction, check 'parameter', 'param', 'fuzzing_parameter'
    parameter_candidates = [
        alert.get("parameter"),
        alert.get("param"),
        alert.get("fuzzing_parameter"), # For Nuclei
        alert.get("meta", {}).get("fuzzing_parameter") # Check nested meta.fuzzing_parameter
    ]
    normalized_parameter = next((p for p in parameter_candidates if p), "")

    normalized = {
        "title": normalized_title,
        "severity": normalized_severity,
        # Use confidence from alert if available, else default
        "confidence": str(alert.get("confidence", alert.get("info", {}).get("confidence", "medium"))),
        "description": normalized_description,
        "remediation": normalized_remediation,
        "background": normalized_background,
        "urls": [str(u) for u in urls if u],
        "paths": [str(p) for p in paths if p],
        "parameter": normalized_parameter,
        "reference": normalized_reference,
        "curl_command": str(alert.get("curl_command", "") or alert.get("curl-command", "")), # Handle both cases
        "http_request": str(alert.get("http_request", "") or alert.get("request", "")), # Handle both cases
        "tool": tool
    }
    # Clean out empty values, but keep empty lists for urls/paths
    return {k: v for k, v in normalized.items() if v or (isinstance(v, list))}


# --- Categorization Helper (keep from previous version) ---
def categorize_alert(tool_name, alert_title):
    """Finds category for an alert title using the reverse_map."""
    if not alert_title or not isinstance(alert_title, str):
        return {"category": "Uncategorized", "tool": tool_name}
    key = alert_title.lower().strip()
    # Return "Uncategorized" if not found in the map
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
                    # Add severity to the alert dict itself for normalization
                    alert["severity"] = severity
                    result.append(alert)
        else:
            logging.warning(f"Burp alerts entry for severity '{severity}' is not a list.")
    return result

# --- Add Alerts Function (Modified for Nuclei, WhatWeb, Wafw00f) ---
def add_alerts(tool, data):
    """Processes and adds alerts from a tool's data to the intermediate_alerts structure."""
    if not data:
        logging.warning(f"No data loaded for tool: {tool}")
        return

    logging.info(f"Processing data for tool: {tool}")

    # --- Specific Tool Handlers ---
    if tool == "Burp Suite":
        alerts_list = flatten_burp(data)
        for alert in alerts_list:
            # Use the normalized title for categorization
            norm_alert_temp = normalize_alert(tool, alert)
            info = categorize_alert(tool, norm_alert_temp.get("title"))
            category = info["category"]
            intermediate_alerts[category][tool].append(norm_alert_temp)

    elif tool == "ZAP":
        if isinstance(data, list):
            for alert in data:
                if isinstance(alert, dict):
                    norm_alert_temp = normalize_alert(tool, alert)
                    info = categorize_alert(tool, norm_alert_temp.get("title"))
                    category = info["category"]
                    intermediate_alerts[category][tool].append(norm_alert_temp)
                else:
                    logging.warning(f"Skipping non-dictionary item in ZAP data: {alert}")
        else:
            logging.warning(f"ZAP data is not a list: {type(data)}")

    elif tool == "Wapiti":
        if isinstance(data, dict) and "vulnerabilities" in data and isinstance(data["vulnerabilities"], dict):
            for name, alerts_list in data["vulnerabilities"].items():
                if isinstance(alerts_list, list):
                    # Categorize based on the group name 'name' from Wapiti
                    info = categorize_alert(tool, name)
                    category = info["category"]
                    for alert in alerts_list:
                        if isinstance(alert, dict):
                            # Add name to alert if missing, helps normalize_alert find title
                            if "name" not in alert and "alert" not in alert and "title" not in alert:
                                alert["name"] = name
                            intermediate_alerts[category][tool].append(normalize_alert(tool, alert))
                        else:
                            logging.warning(f"Skipping non-dictionary alert in Wapiti list for '{name}': {alert}")
                else:
                    logging.warning(f"Alerts list for Wapiti vulnerability '{name}' is not a list.")
        else:
            logging.warning(f"Wapiti data format unexpected: {type(data)}")

    elif tool == "Wafw00f":
        category = "Firewall Detected" # Specific category
        processed = False
        if isinstance(data, dict) and "firewalls_detected" in data:
            detected_list = data["firewalls_detected"]
            if isinstance(detected_list, list) and detected_list:
                logging.info(f"Found {len(detected_list)} firewall detections from Wafw00f.")
                for fw_info in detected_list:
                    if isinstance(fw_info, dict):
                         # Use normalize_alert for consistency, passing a constructed dict
                        waf_entry_raw = {
                            "name": f"Detected: {fw_info.get('firewall', 'Unknown Firewall')}",
                            "severity": "info",
                            "description": f"Manufacturer: {fw_info.get('manufacturer', 'Unknown')}. Detected on URL: {fw_info.get('url', 'N/A')}",
                            "url": fw_info.get('url', None) # Pass URL for normalization
                        }
                        intermediate_alerts[category][tool].append(normalize_alert(tool, waf_entry_raw))
                        processed = True
                    else:
                        logging.warning(f"Skipping non-dictionary item in Wafw00f detected_list: {fw_info}")
            else:
                logging.info("Wafw00f ran but detected no firewalls (empty list).")
                processed = True # Consider it processed even if none found

        if not processed:
             logging.warning(f"Wafw00f data format unexpected or missing 'firewalls_detected': {type(data)}")


    elif tool == "WhatWeb":
        category = "Technologies Detected" # Specific category
        processed = False
        if isinstance(data, dict) and "technologies" in data:
            tech_dict = data.get("technologies", {})
            if tech_dict: # Check if technologies were actually found
                logging.info(f"Found {len(tech_dict)} technology types from WhatWeb.")
                for tech_name, details_list in tech_dict.items():
                    description = ""
                    # Extract description strings more robustly
                    found_strings = []
                    if isinstance(details_list, list):
                         for details in details_list:
                             if isinstance(details, dict) and "string" in details:
                                 s = details["string"]
                                 if isinstance(s, list): found_strings.extend(s)
                                 elif isinstance(s, str): found_strings.append(s)
                    elif isinstance(details_list, dict) and "string" in details_list:
                         s = details_list["string"]
                         if isinstance(s, list): found_strings.extend(s)
                         elif isinstance(s, str): found_strings.append(s)

                    if found_strings:
                        description = "Evidence: " + ", ".join(list(set(found_strings))) # Unique strings

                    # Use normalize_alert for consistency
                    tech_alert_raw = {
                        "name": f"{tech_name} Detected", # More specific title part
                        "severity": "info", # Technology detection is informational
                        "description": f"Target: {data.get('target_url', 'N/A')} (Status: {data.get('http_status', 'N/A')}). {description}".strip(),
                        "url": data.get('target_url', None) # Pass URL for normalization
                    }
                    intermediate_alerts[category][tool].append(normalize_alert(tool, tech_alert_raw))
                    processed = True
            else:
                logging.info(f"WhatWeb ran but detected no technologies.")
                processed = True # Processed even if none found
        if not processed:
            logging.warning(f"WhatWeb data format unexpected or missing 'technologies': {type(data)}")


    # --- NEW: Specific Handler for Nuclei ---
    elif tool == "Nuclei":
        category = "Nuclei Findings" # Dedicated category
        if isinstance(data, list):
            logging.info(f"Processing {len(data)} findings from Nuclei.")
            for alert_item in data:
                if isinstance(alert_item, dict):
                    # normalize_alert is designed to handle the Nuclei structure now
                    # It checks info.name, info.severity, info.description, template-url etc.
                    normalized = normalize_alert(tool, alert_item)
                    intermediate_alerts[category][tool].append(normalized)
                else:
                    logging.warning(f"Skipping non-dictionary item in Nuclei data: {alert_item}")
        else:
            logging.warning(f"Nuclei data format unexpected: Expected a list, got {type(data)}")


    # --- Generic/Else block for other tools (like Nikto or uncategorized) ---
    else:
        logging.info(f"Processing tool '{tool}' with generic vulnerability handler.")
        alerts_to_add = []
        if isinstance(data, list):
             # Assume list of alert dicts is the most common fallback
            for alert in data:
                if isinstance(alert, dict):
                    norm_alert_temp = normalize_alert(tool, alert)
                    # Try to categorize even for generic tools
                    info = categorize_alert(tool, norm_alert_temp.get("title"))
                    category = info["category"] # Use categorized or 'Uncategorized'
                    intermediate_alerts[category][tool].append(norm_alert_temp)
                else:
                     logging.warning(f"Skipping non-dictionary item in generic list data for {tool}: {alert}")

        # Handle Nikto's potential structure if it's dict-based (less common for modern parsers)
        elif isinstance(data, dict) and "vulnerabilities" in data and isinstance(data.get("vulnerabilities"), list):
            logging.info(f"Processing Nikto-like structure for tool '{tool}'.")
            for alert in data["vulnerabilities"]:
                 if isinstance(alert, dict):
                    norm_alert_temp = normalize_alert(tool, alert)
                    # Try to categorize
                    info = categorize_alert(tool, norm_alert_temp.get("title"))
                    category = info["category"]
                    intermediate_alerts[category][tool].append(norm_alert_temp)
                 else:
                     logging.warning(f"Skipping non-dictionary item in Nikto vulnerabilities list for {tool}: {alert}")

        else:
            # Fallback: Treat the entire data as a single placeholder if format is unknown
            logging.warning(f"Data format for '{tool}' not recognized by generic handler: {type(data)}. Storing placeholder.")
            category = "Uncategorized"
            placeholder_alert = {
                "title": f"Unprocessed Data from {tool}",
                "severity": "info",
                "description": f"Raw data snippet: {str(data)[:500]}...",
                "tool": tool
            }
            # No need to normalize the placeholder itself
            intermediate_alerts[category][tool].append(placeholder_alert)


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
processed_categories = set() # Keep track of what's added

# Define the desired order
category_order = ["Firewall Detected", "Technologies Detected", "Nuclei Findings"]

# Add predefined categories in order
for category_name in category_order:
    if category_name in intermediate_alerts:
        final_alerts_ordered[category_name] = intermediate_alerts[category_name]
        processed_categories.add(category_name)
        logging.info(f"Added '{category_name}' category to final output.")

# Add remaining categories (can sort them alphabetically)
other_categories = sorted([cat for cat in intermediate_alerts if cat not in processed_categories])

for category in other_categories:
    final_alerts_ordered[category] = intermediate_alerts[category]
    processed_categories.add(category) # Not strictly needed now, but good practice
    logging.info(f"Added '{category}' category to final output.")


# --- Save Final Output ---
output_filename = "final_alerts.json"
logging.info(f"Saving combined and ordered results to {output_filename}")
try:
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_filename)
    # Handle case where output_filename has no directory part
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"Created output directory: {output_dir}")

    with open(output_filename, "w", encoding='utf-8') as f:
        # Use the ordered dictionary for saving
        json.dump(final_alerts_ordered, f, indent=4)
    logging.info(f"{output_filename} has been created successfully.")
except Exception as e:
    # Use logging.exception to include traceback
    logging.exception(f"Error saving final output to {output_filename}: {e}")