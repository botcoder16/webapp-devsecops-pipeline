import json
import sys
import os
import logging

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_whatweb(input_file, output_file):
    """
    Parses WhatWeb JSON output to extract target URL, status, and detected technologies.

    Args:
        input_file (str): Path to the WhatWeb JSON input file.
        output_file (str): Path to save the cleaned JSON output file.
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # WhatWeb output is typically a list
            data = json.load(f)

        if not isinstance(data, list) or len(data) < 3:
            logging.error(f"Invalid WhatWeb JSON format in {input_file}. Expected a list with at least 3 elements.")
            # Create an empty output file to signify parsing failure but allow pipeline to continue
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({"error": "Invalid input format"}, f, indent=2)
            return

        target_url = data[0]
        status_code = data[1]
        raw_technologies = data[2]

        # Structure the detected technologies into a dictionary {name: details_list}
        detected_technologies = {}
        if isinstance(raw_technologies, list):
            for tech_item in raw_technologies:
                if isinstance(tech_item, list) and len(tech_item) >= 2:
                    tech_name = tech_item[0]
                    tech_details = tech_item[1]
                    if isinstance(tech_name, str) and isinstance(tech_details, list):
                         # Ensure details list contains dictionaries
                         valid_details = [detail for detail in tech_details if isinstance(detail, dict)]
                         if valid_details: # Only add if there are valid details
                              detected_technologies[tech_name] = valid_details
                    else:
                         logging.warning(f"Skipping unexpected technology item format: {tech_item}")
                else:
                    logging.warning(f"Skipping unexpected item format in technology list: {tech_item}")


        # Build the cleaned output structure
        cleaned_data = {
            "target_url": target_url,
            "http_status": status_code,
            "technologies": detected_technologies # Dictionary of detected technologies
        }

        # Save the cleaned data to the output file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cleaned_data, f, indent=2)
        logging.info(f"Successfully parsed WhatWeb output and saved to {output_file}")

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
        print("Usage: python whatweb_parser.py <input_whatweb.json> <output_parsed.json>")
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


    parse_whatweb(input_path, output_path)