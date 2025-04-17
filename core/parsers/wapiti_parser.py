import json
import sys
import os

def wapiti_vulnerabilities(input_file, output_file):
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
        
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py input_file.json output_file.json")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(input_path):
        print(f"Input file does not exist: {input_path}")
        sys.exit(1)

    wapiti_vulnerabilities(input_path, output_path)