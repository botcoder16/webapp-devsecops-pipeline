import sys
import json
import subprocess # Added for running parsers/combine
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor
import logging
import requests # Keep requests for API calls

# --- Core Command/Scanner Imports ---
from core.commands.generate_nuclei_command import generate_nuclei_command
from core.commands.generate_wapiti_command import generate_wapiti_command
from core.commands.nikto import generate_nikto_command
from core.commands.wafw00f import generate_wafw00f_command
from core.commands.whatweb import generate_whatweb_command
from core.scanner.zap_scan import execute_zap_scan
from core.scanner.burp_pro_scan import execute_burp_scan

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Determine script directory for relative paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "core", "scan_results")
COMBINE_DIR = os.path.join(SCRIPT_DIR, "core", "combine")
PARSERS_DIR = os.path.join(SCRIPT_DIR, "core", "parsers")
VULN_DIR = os.path.join(COMBINE_DIR, "vulnerabilities") # Output dir for parsers
FINAL_REPORT_PATH = os.path.join(COMBINE_DIR, "final_alerts.json")

API_URL = "http://192.168.111.134:5000/scan" # Adjust if needed
API_ZIP_FILE = "scan_results.zip"

# --- Helper Function ---
def ensure_dir(directory_path):
    """Creates a directory if it doesn't exist."""
    os.makedirs(directory_path, exist_ok=True)


# --- Scan Execution Functions (Modified for consistent output paths) ---

def run_api_scan(options):
    """Execute API scan with options derived from input JSON"""
    try:
        logging.info("[API] Starting API tools scan...")
        selected_tools = options.get("selected_tools", {})
        commands = {}
        tool_output_files = {} # Track expected output files for parsing

        # Ensure base output directory exists
        ensure_dir(OUTPUT_DIR)

        # --- Generate Commands & Define Output Paths ---
        if selected_tools.get("use_nuclei"):
            # Nuclei outputs directly to specified path in command
            nuclei_output_path = os.path.join(OUTPUT_DIR, 'nuclei', 'nuclei_scan.json')
            ensure_dir(os.path.dirname(nuclei_output_path))
            # Modify options to include absolute path for nuclei output
            options['nuclei_output_path'] = nuclei_output_path # Add a key for the path
            commands["nuclei"] = generate_nuclei_command(options, use_absolute_path=True) # Pass flag to generate command
            tool_output_files["nuclei"] = nuclei_output_path
            logging.info(f"[API] Generated Nuclei command: {commands['nuclei']}")

        if selected_tools.get("use_wapiti"):
            # Wapiti outputs directly to specified path in command
            wapiti_output_path = os.path.join(OUTPUT_DIR, 'wapiti', 'wapiti_scan.json')
            ensure_dir(os.path.dirname(wapiti_output_path))
            options['wapiti_output_path'] = wapiti_output_path # Add a key for the path
            commands["wapiti"] = generate_wapiti_command(options, use_absolute_path=True) # Pass flag to generate command
            tool_output_files["wapiti"] = wapiti_output_path
            logging.info(f"[API] Generated Wapiti command: {commands['wapiti']}")

        if selected_tools.get("use_nikto"): # Assuming nikto is optional
            # Nikto outputs XML, needs specific path
            nikto_output_path = os.path.join(OUTPUT_DIR, 'nikto', 'nikto_scan.xml')
            ensure_dir(os.path.dirname(nikto_output_path))
            options['nikto_output_path'] = nikto_output_path
            commands["nikto"] = generate_nikto_command(options, use_absolute_path=True)
            tool_output_files["nikto"] = nikto_output_path # Although no parser exists yet
            logging.info(f"[API] Generated Nikto command: {commands['nikto']}")

        if selected_tools.get("use_wafw00f"): # Assuming wafw00f is optional
            # Wafw00f - currently doesn't specify output, assume stdout handled by server_api
             commands["wafw00f"] = generate_wafw00f_command(options)
             logging.info(f"[API] Generated Wafw00f command: {commands['wafw00f']}")
             # No output file to parse directly specified here

        if selected_tools.get("use_whatweb"): # Assuming whatweb is optional
             # WhatWeb outputs directly to specified path
             whatweb_output_path = os.path.join(OUTPUT_DIR, 'whatweb', 'whatweb_scan.json')
             ensure_dir(os.path.dirname(whatweb_output_path))
             options['whatweb_output_path'] = whatweb_output_path
             commands["whatweb"] = generate_whatweb_command(options, use_absolute_path=True)
             tool_output_files["whatweb"] = whatweb_output_path # Although no parser exists yet
             logging.info(f"[API] Generated WhatWeb command: {commands['whatweb']}")


        if not commands:
            logging.warning("[API] No API tools selected or commands generated.")
            return {'status': 'skipped', 'reason': 'No API tools selected', 'output_files': {}}

        payload = {"commands": commands}
        logging.info(f"[API] Sending payload to API: {payload}")

        # --- Execute API Request ---
        try:
            response = requests.post(API_URL, json=payload, headers={"Content-Type": "application/json"}, timeout=1800) # Increased timeout
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        except requests.exceptions.Timeout:
             logging.error("[API] Scan request timed out.")
             return {'status': 'failed', 'error': 'API request timed out', 'output_files': tool_output_files}
        except requests.exceptions.RequestException as e:
             logging.error(f"[API] Scan request failed: {e}")
             return {'status': 'failed', 'error': f"API error: {e}", 'response': getattr(e.response, 'text', 'No response text'), 'output_files': tool_output_files}


        # --- Process API Response (assuming zip for some tools if not outputting directly) ---
        # This part needs adjustment if server_api.py handles all output saving directly
        # Assuming server_api.py places files in the *expected* locations defined above

        logging.info("[API] Scan request successful. Checking for output files.")
        # Verification step (optional but recommended): Check if expected files exist
        for tool, path in tool_output_files.items():
            if not os.path.exists(path):
                 logging.warning(f"[API] Expected output file for {tool} not found at {path}")
            else:
                 logging.info(f"[API] Confirmed output file for {tool} at {path}")


        return {
            'status': 'completed',
            'output_dir': OUTPUT_DIR, # Main output dir
            'output_files': tool_output_files # Dictionary of {tool_name: output_path}
        }

    except Exception as e:
        logging.exception("[API] Unexpected error during API scan:") # Log full traceback
        return {'status': 'error', 'error': str(e), 'output_files': tool_output_files if 'tool_output_files' in locals() else {}}


def run_zap_scan(zap_config):
    """Execute ZAP scan with configuration derived from input JSON"""
    try:
        logging.info("[ZAP] Starting ZAP scan...")
        if not zap_config or 'target_url' not in zap_config:
             logging.error("[ZAP] Insufficient ZAP configuration provided.")
             return {'status': 'failed', 'error': 'Insufficient ZAP configuration'}

        # Ensure output directory exists
        ensure_dir(os.path.dirname(zap_config['report_path']))
        logging.info(f"[ZAP] Report will be saved to: {zap_config['report_path']}")

        result = execute_zap_scan(zap_config) # execute_zap_scan needs zap_config dict

        # Add the output file path to the result for consistency
        if result.get('status') == 'completed':
            result['output_files'] = {'zap': zap_config['report_path']}
        else:
            result['output_files'] = {}

        return result

    except Exception as e:
        logging.exception("[ZAP] Error during ZAP scan:")
        return {'status': 'error', 'error': str(e), 'output_files': {}}

def run_burp_scan(burp_config):
    """Execute Burp scan with configuration derived from input JSON"""
    try:
        logging.info("[BURP] Starting Burp scan...")
        if not burp_config or 'target_url' not in burp_config:
            logging.error("[BURP] Insufficient Burp configuration provided.")
            return {'status': 'failed', 'error': 'Insufficient Burp configuration'}

        # Ensure output directory exists
        ensure_dir(os.path.dirname(burp_config['report_path']))
        logging.info(f"[BURP] Report will be saved to: {burp_config['report_path']}")

        result = execute_burp_scan(burp_config) # execute_burp_scan needs burp_config dict

        # Add the output file path to the result for consistency
        if result.get('status') == 'completed':
            result['output_files'] = {'burp': burp_config['report_path']}
        else:
            result['output_files'] = {}
        return result

    except Exception as e:
        logging.exception("[BURP] Error during Burp scan:")
        return {'status': 'error', 'error': str(e), 'output_files': {}}


# --- NEW: Parsing and Combining Functions ---

def run_parsers(scan_results):
    """Runs the necessary parsers on the generated scan output files."""
    logging.info("=== Running Parsers ===")
    ensure_dir(VULN_DIR)
    parser_success = True

    # Define parser mappings: tool_name -> (parser_script, input_suffix, output_suffix)
    parser_map = {
        "zap": ("zap_parser.py", "zap_scan.json", "vulnerabilities_zap.json"),
        "burp": ("burp_parser.py", "burp_scan.json", "vulnerabilities_burp.json"),
        "wapiti": ("wapiti_parser.py", "wapiti_scan.json", "vulnerabilities_wapiti.json"),
        "nuclei": ("nuclei_parser.py", "nuclei_scan.json", "vulnerabilities_nuclei.json"),
        # Add other parsers here if needed (e.g., nikto, whatweb)
    }

    all_output_files = {}
    for result in scan_results:
        all_output_files.update(result.get('output_files', {}))

    logging.info(f"Attempting to parse files: {all_output_files}")

    for tool, (parser_script, input_suffix, output_suffix) in parser_map.items():
        if tool in all_output_files:
            input_file = all_output_files[tool]
            parser_path = os.path.join(PARSERS_DIR, parser_script)
            output_file = os.path.join(VULN_DIR, output_suffix)

            if os.path.exists(input_file) and os.path.exists(parser_path):
                logging.info(f"Running parser: {parser_script} on {input_file}")
                try:
                    # Use absolute paths for parser arguments
                    cmd = ["python3", parser_path, input_file, output_file]
                    # Run parser with explicit input/output args
                    # Note: Assumes parsers are updated to accept args: script.py <input_file> <output_file>
                    # If parsers read/write hardcoded paths, this needs adjustment or parsers need modification.
                    # Based on fetched parser code, they *do* seem to expect args.
                    process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
                    logging.info(f"Parser {parser_script} output:\n{process.stdout}")
                    if process.stderr:
                         logging.warning(f"Parser {parser_script} stderr:\n{process.stderr}")
                    if not os.path.exists(output_file):
                         logging.error(f"Parser {parser_script} ran but output file {output_file} not found!")
                         parser_success = False

                except subprocess.CalledProcessError as e:
                    logging.error(f"Error running parser {parser_script} on {input_file}: {e}")
                    logging.error(f"Stderr: {e.stderr}")
                    parser_success = False
                except subprocess.TimeoutExpired:
                    logging.error(f"Parser {parser_script} timed out.")
                    parser_success = False
                except Exception as e:
                    logging.exception(f"Unexpected error running parser {parser_script}:")
                    parser_success = False
            elif not os.path.exists(input_file):
                 logging.warning(f"Input file {input_file} for parser {parser_script} not found. Skipping.")
            elif not os.path.exists(parser_path):
                 logging.error(f"Parser script {parser_path} not found. Cannot parse {tool} results.")
                 parser_success = False # Indicate failure if parser script is missing
        else:
            logging.info(f"No output file found for tool '{tool}'. Skipping parser.")


    if not parser_success:
         logging.error("One or more parsers failed to execute correctly.")
    return parser_success


def run_combiner():
    """Runs the combine.py script."""
    logging.info("=== Running Combiner ===")
    combiner_script = os.path.join(COMBINE_DIR, "combine.py")

    if not os.path.exists(combiner_script):
        logging.error(f"Combiner script not found at {combiner_script}")
        return False

    try:
        # Run combine.py from the COMBINE_DIR so its relative paths work
        process = subprocess.run(
            ["python3", os.path.basename(combiner_script)], # Run script by name
            capture_output=True,
            text=True,
            check=True,
            cwd=COMBINE_DIR, # Set working directory
            timeout=60
        )
        logging.info(f"Combiner output:\n{process.stdout}")
        if process.stderr:
             logging.warning(f"Combiner stderr:\n{process.stderr}")

        # Verify final output file exists
        if os.path.exists(FINAL_REPORT_PATH):
             logging.info(f"Final report successfully created at: {FINAL_REPORT_PATH}")
             return True
        else:
             logging.error(f"Combiner script ran but final report {FINAL_REPORT_PATH} was not created.")
             return False

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running combiner script: {e}")
        logging.error(f"Stderr: {e.stderr}")
        return False
    except subprocess.TimeoutExpired:
        logging.error("Combiner script timed out.")
        return False
    except Exception as e:
        logging.exception("Unexpected error running combiner script:")
        return False

# --- Main Execution Logic ---

def main(options_data):
    """Main function accepting options dictionary"""
    ensure_dir(OUTPUT_DIR) # Ensure base output dir exists

    selected_tools = options_data.get("selected_tools", {})
    use_api_tools = any(selected_tools.get(tool) for tool in ["use_wapiti", "use_nuclei", "use_nikto", "use_wafw00f", "use_whatweb"])
    use_zap = selected_tools.get("use_zap", False)
    use_burp = selected_tools.get("use_burp", False)

    if not (use_api_tools or use_zap or use_burp):
        logging.warning("No tools selected for scanning.")
        print("{\"status\": \"no_tools_selected\"}") # Output JSON status
        return # Exit if no tools

    logging.info("=== Starting All Selected Scans ===")

    # --- Prepare configurations from options_data ---
    api_options = options_data if use_api_tools else None
    zap_config = {}
    burp_config = {}

    # Construct zap_config if ZAP is selected
    if use_zap:
        zap_output_path = os.path.join(OUTPUT_DIR, 'zap', 'zap_scan.json')
        zap_config = {
            'target_url': options_data.get('target_url'),
            'scan_policy': options_data.get('zap_scan_policy', 'Default Policy'),
            'delay_in_ms': int(options_data.get('zap_delay', 100)),
            'threads_per_host': int(options_data.get('zap_threads', 5)),
            'credentials': options_data.get('zap_credentials'),
            'report_path': zap_output_path # Use absolute path
        }
        logging.info(f"ZAP Config: {zap_config}")


    # Construct burp_config if Burp is selected
    if use_burp:
        burp_output_path = os.path.join(OUTPUT_DIR, 'burp', 'burp_scan.json')
        burp_config = {
            'target_url': options_data.get('target_url'),
            'scan_config': { # Use the nested structure expected by burp scanner
                 "name": options_data.get('burp_scan_config', 'Crawl and Audit - Balanced'),
                 "type": "NamedConfiguration"
            },
            'credentials': options_data.get('burp_credentials'),
            'report_path': burp_output_path # Use absolute path
        }
        logging.info(f"Burp Config: {burp_config}")


    # --- Execute scans concurrently ---
    scan_results = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        if use_api_tools and api_options:
            futures.append(executor.submit(run_api_scan, api_options))
        if use_zap:
            futures.append(executor.submit(run_zap_scan, zap_config))
        if use_burp:
            futures.append(executor.submit(run_burp_scan, burp_config))

        # Collect results
        for future in futures:
             try:
                 result = future.result()
                 scan_results.append(result)
             except Exception as exc:
                 logging.error(f'Scan task generated an exception: {exc}')
                 scan_results.append({'status': 'error', 'error': str(exc), 'output_files': {}})


    # --- Report Scan Results ---
    logging.info("\n=== Scan Execution Summary ===")
    all_scans_ok = True
    for result in scan_results:
         status = result.get('status', 'unknown')
         tool_name = "Unknown Scan"
         # Basic identification (could be improved)
         if 'output_files' in result and result['output_files']:
             tool_name = list(result['output_files'].keys())[0].capitalize() + " Scan" if len(result['output_files']) == 1 else "API Scan"
         elif 'alerts_count' in result: tool_name = "ZAP Scan"
         elif 'issues_count' in result: tool_name = "Burp Scan"

         logging.info(f"[{tool_name}]: Status: {status}")
         if status not in ['completed', 'succeeded', 'skipped']:
             logging.error(f"  Error: {result.get('error', 'Unknown error')}")
             all_scans_ok = False # Mark as failed if any scan fails (excluding skipped)
         elif status == 'completed' or status == 'succeeded':
             logging.info(f"  Output Files: {result.get('output_files', 'N/A')}")

    if not all_scans_ok:
        logging.error("One or more scans failed. Skipping parsing and combining.")
        print("{\"status\": \"scan_failed\"}") # Output JSON status
        return # Exit if scans failed

    # --- Run Parsers ---
    parsers_ok = run_parsers(scan_results)
    if not parsers_ok:
        logging.error("Parsing failed. Skipping combining.")
        print("{\"status\": \"parsing_failed\"}") # Output JSON status
        return # Exit if parsing failed

    # --- Run Combiner ---
    combiner_ok = run_combiner()
    if not combiner_ok:
         logging.error("Combining failed.")
         print("{\"status\": \"combining_failed\"}") # Output JSON status
         return # Exit if combining failed

    # --- Final Success ---
    logging.info("=== Processing Pipeline Completed Successfully ===")
    print(json.dumps({"status": "success", "report_path": FINAL_REPORT_PATH})) # Output JSON status


# --- Command Line Execution ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py '<json_options_string>'")
        print("Example: python main.py '{\"target_url\": \"http://example.com\", \"selected_tools\": {\"use_zap\": true}}'")
        sys.exit(1)

    json_options_string = sys.argv[1]
    try:
        options = json.loads(json_options_string)
        logging.info("Successfully parsed options JSON from command line.")
        main(options) # Pass the dictionary directly
    except json.JSONDecodeError:
        logging.error("Error: Invalid JSON string provided as argument.")
        print("{\"status\": \"invalid_json_input\"}")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred during execution:")
        print(f"{{\"status\": \"runtime_error\", \"error\": \"{str(e)}\"}}")
        sys.exit(1)
