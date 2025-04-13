import json

def extract_non_empty_vulnerabilities(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Get only non-empty vulnerabilities
    non_empty_vulns = {
        vuln_name: details
        for vuln_name, details in data.get("vulnerabilities", {}).items()
        if details  # Keep only if there are actual findings
    }

    # Build cleaned structure
    cleaned_data = {
        "vulnerabilities": non_empty_vulns
    }

    # Save to output file
    with open(output_file, 'w') as f:
        json.dump(cleaned_data, f, indent=2)

# Example usage
extract_non_empty_vulnerabilities("../scan_results/wapiti/wapiti_scan.json", "../combine/vulnerabilities_wapiti.json")
