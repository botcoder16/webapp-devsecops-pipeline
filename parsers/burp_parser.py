import json

def parse_scan_results(file_path, output_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    
    vulnerabilities = {"info": [], "low": [], "medium": [], "high": [], "critical": []}
    
    for issue in data.get("issues", []):
        issue_data = issue.get("issue", {})
        name = issue_data.get("name", "Unknown Issue")
        severity = issue_data.get("severity", "unknown").lower()
        description = issue_data.get("description", "No description available.")
        path = issue_data.get("path", "Unknown Path")
        origin = issue_data.get("origin", "Unknown Origin")
        
        vulnerabilities.setdefault(severity, []).append({
            "name": name,
            "path": path,
            "origin": origin,
            "description": description,
            "issue_background": issue_data.get("issue_background", "No background information available."),
            "remediation_background": issue_data.get("remediation_background", "No remediation information available."),
        })
    
    with open(output_path, 'w', encoding='utf-8') as output_file:
        json.dump(vulnerabilities, output_file, indent=4)

# Example Usage
file_path = "../scan_results/burp/burp_scan.json"
output_path = "../combine/vulnerabilities_burp.json"
parse_scan_results(file_path, output_path)

print(f"Parsed vulnerabilities saved to {output_path}")
