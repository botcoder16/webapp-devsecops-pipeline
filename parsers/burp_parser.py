import json

def parse_scan_results(file_path, output_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    # Dictionary to group alerts by name + origin
    grouped = {}

    for issue in data.get("issues", []):
        issue_data = issue.get("issue", {})
        name = issue_data.get("name", "Unknown Issue")
        type_index = issue_data.get("type_index", "Unknown Type Index")
        severity = issue_data.get("severity", "unknown").lower()
        confidence = issue_data.get("confidence", "unknown").lower()
        description = issue_data.get("description", "No description available.")
        path = issue_data.get("path", "Unknown Path")
        origin = issue_data.get("origin", "Unknown Origin")
        issue_background = issue_data.get("issue_background", "No background information available.")
        remediation_background = issue_data.get("remediation_background", "No remediation information available.")

        key = (name, origin)

        if key not in grouped:
            grouped[key] = {
                "name": name,
                "type_index": type_index,
                "origin": origin,
                "confidence": confidence,
                "description": description,
                "issue_background": issue_background,
                "remediation_background": remediation_background,
                "paths": [],
                "severity": severity
            }

        grouped[key]["paths"].append(path)

    # Final structure organized by severity
    vulnerabilities = {"info": [], "low": [], "medium": [], "high": [], "critical": []}

    for item in grouped.values():
        severity = item.pop("severity")
        vulnerabilities.setdefault(severity, []).append(item)

    with open(output_path, 'w', encoding='utf-8') as output_file:
        json.dump(vulnerabilities, output_file, indent=4)

# Example Usage
file_path = "../scan_results/burp/burp_scan.json"
output_path = "../combine/vulnerabilities_burp.json"
parse_scan_results(file_path, output_path)

print(f"Parsed vulnerabilities saved to {output_path}")
