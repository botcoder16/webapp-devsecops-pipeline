import xml.etree.ElementTree as ET
import json
import sys
import os

def nikto_vulnerabilities(input_file, output_file):

    # Parse the XML file
    try:
        tree = ET.parse(input_file)
        root = tree.getroot()
    except Exception as e:
        print(f"Error reading XML file: {e}")
        return

    # Initialize the list to store vulnerabilities
    vulnerabilities = []

    # Iterate through each <item> element to extract vulnerability data
    for item in root.findall(".//item"):
        vulnerability = {
            "id": item.get("id"),
            "description": item.find("description").text.strip() if item.find("description") is not None else "",
            "uri": item.find("uri").text.strip() if item.find("uri") is not None else "",
            "namelink": item.find("namelink").text.strip() if item.find("namelink") is not None else "",
            "iplink": item.find("iplink").text.strip() if item.find("iplink") is not None else "",
            "osvdbid": item.get("osvdbid"),
            "osvdblink": item.get("osvdblink"),
            "method": item.get("method")
        }
        vulnerabilities.append(vulnerability)

    # Save vulnerabilities to the output JSON file
    try:
        with open(output_file, "w") as json_file:
            json.dump(vulnerabilities, json_file, indent=4)
        print(f"Vulnerabilities have been saved to {output_file}")
    except Exception as e:
        print(f"Error writing to JSON file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py input_file.json output_file.json")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(input_path):
        print(f"Input file does not exist: {input_path}")
        sys.exit(1)
nikto_vulnerabilities(input_path, output_path)