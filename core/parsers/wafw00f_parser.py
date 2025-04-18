import json
import sys
import os
import logging

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_wafw00f(input_file, output_file):
    """
    Parses WAFW00F JSON output to extract detected firewalls.

    Args:
        input_file (str): Path to the WAFW00F JSON input file.
        output_file (str): Path to save the cleaned JSON output file.
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # WAFW00F output is typically a list of dictionaries
            data = json.load(f)

        if not isinstance(data, list):
            logging.error(f"Invalid WAFW00F JSON format in {input_file}. Expected a list.")
            # Create an empty output file to signify parsing failure
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({"error": "Invalid input format, expected a list"}, f, indent=2)
            return

        # Filter for entries where a firewall was detected
        detected_firewalls = []
        for item in data:
            if isinstance(item, dict) and item.get("detected") is True:
                # Extract relevant details for detected firewalls
                firewall_info = {
                    "firewall": item.get("firewall", "Unknown"),
                    "manufacturer": item.get("manufacturer", "Unknown"),
                    "url": item.get("url") # Include the URL tested
                    # Optionally include "trigger_url" if needed:
                    # "trigger_url": item.get("trigger_url")
                }
                detected_firewalls.append(firewall_info)

        # Build the cleaned output structure
        cleaned_data = {
            "firewalls_detected": detected_firewalls
        }

        # Save the cleaned data to the output file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned_data, f, indent=2)
        logging.info(f"Successfully parsed WAFW00F output and saved to {output_file}")

    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {input_file}: {e}")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({"error": f"JSON decode error: {e}"}, f, indent=2)
    except Exception as e:
        logging.error(f"An unexpected error occurred during parsing: {e}")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({"error": f"Unexpected error: {e}"}, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python wafw00f_parser.py <input_wafw00f.json> <output_parsed.json>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(input_path):
        print(f"Error: Input file does not exist: {input_path}")
        sys.exit(1)

    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logging.info(f"Created output directory: {output_dir}")
        except OSError as e:
            print(f"Error creating output directory {output_dir}: {e}")
            sys.exit(1)

    parse_wafw00f(input_path, output_path)