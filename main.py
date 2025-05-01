import sys
import json
import subprocess # Added for running parsers/combine
import os
import zipfile # Added for zip extraction
import io      # Added for handling zip in memory if needed, but file better
from concurrent.futures import ThreadPoolExecutor
import logging
import requests # Keep requests for API calls
import time # For timing if needed

# --- Core Command Generation Imports (Scanners Removed) ---
from core.commands.generate_nuclei_command import generate_nuclei_command
from core.commands.generate_wapiti_command import generate_wapiti_command
from core.commands.nikto import generate_nikto_command
from core.commands.wafw00f import generate_wafw00f_command
from core.commands.whatweb import generate_whatweb_command
# REMOVED: from core.scanner.zap_scan import execute_zap_scan
# REMOVED: from core.scanner.burp_pro_scan import execute_burp_scan

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',handlers=[
        logging.StreamHandler(sys.stdout)
    ])

logger = logging.getLogger(__name__)
# Determine script directory for relative paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "core", "scan_results") # Base dir for extracted results
COMBINE_DIR = os.path.join(SCRIPT_DIR, "core", "combine")
PARSERS_DIR = os.path.join(SCRIPT_DIR, "core", "parsers")
VULN_DIR = os.path.join(COMBINE_DIR, "vulnerabilities") # Output dir for parsers
FINAL_REPORT_PATH = os.path.join(COMBINE_DIR, "final_alerts.json")

# --- API URLs and Filenames ---
UBUNTU_API_URL = "http://192.168.6.144:5000/scan" # URL for Ubuntu API (Nuclei, Wapiti, etc.)
WINDOWS_API_URL = "http://192.168.6.147:5001/scan" # URL for Windows API (Burp, ZAP)

# Using distinct names for received zip files for clarity
UBUNTU_API_ZIP_FILENAME = "ubuntu_api_scan_results.zip"
WINDOWS_API_ZIP_FILENAME = "windows_api_scan_results.zip"
SCAN_SUMMARY_FILENAME = "scan_summary.json" # Expected summary file name inside zips

# --- Helper Function ---
def ensure_dir(directory_path):
    """Creates a directory if it doesn't exist."""
    os.makedirs(directory_path, exist_ok=True)


# --- Scan Execution Functions (API Calls Only) ---

def run_ubuntu_api_scan(options):
    """
    Execute Ubuntu API scan (Nuclei, Wapiti, etc.) with options, expecting a zip file in return.
    Extracts the zip and parses scan_summary.json to determine results.
    """
    logging.info("[UBUNTU API] Starting Ubuntu tools scan...")
    selected_tools = options.get("selected_tools", {})
    commands = {}
    requested_api_tools = []

    # Ensure base output directory exists
    ensure_dir(OUTPUT_DIR)
    api_zip_path = os.path.join(OUTPUT_DIR, UBUNTU_API_ZIP_FILENAME) # Use specific name

    # --- Generate Commands ONLY for Ubuntu tools ---
    if selected_tools.get("use_nuclei"):
        commands["nuclei"] = generate_nuclei_command(options)
        requested_api_tools.append("nuclei")
        logging.info(f"[UBUNTU API] Generated Nuclei command")

    if selected_tools.get("use_wapiti"):
        commands["wapiti"] = generate_wapiti_command(options)
        requested_api_tools.append("wapiti")
        logging.info(f"[UBUNTU API] Generated Wapiti command")

    if selected_tools.get("use_nikto"):
        commands["nikto"] = generate_nikto_command(options)
        requested_api_tools.append("nikto")
        logging.info(f"[UBUNTU API] Generated Nikto command")

    if selected_tools.get("use_wafw00f"):
        commands["wafw00f"] = generate_wafw00f_command(options)
        requested_api_tools.append("wafw00f")
        logging.info(f"[UBUNTU API] Generated Wafw00f command")

    if selected_tools.get("use_whatweb"):
        commands["whatweb"] = generate_whatweb_command(options)
        requested_api_tools.append("whatweb")
        logging.info(f"[UBUNTU API] Generated WhatWeb command")

    # If no tools for this API are selected, skip the call
    if not commands:
        logging.warning("[UBUNTU API] No Ubuntu API tools selected or commands generated.")
        return {'status': 'skipped', 'reason': 'No Ubuntu API tools selected', 'output_files': {}, 'api_source': 'ubuntu'}

    payload = {"commands": commands}
    logging.info(f"[UBUNTU API] Sending payload to {UBUNTU_API_URL} for tools: {list(commands.keys())}")

    # --- Execute API Request ---
    response = None
    try:
        # Use the correct URL and a reasonable timeout for these tools
        response = requests.post(UBUNTU_API_URL, json=payload, headers={"Content-Type": "application/json"}, stream=True, timeout=600) # 10 min timeout
        response.raise_for_status()

    except requests.exceptions.Timeout:
        logging.error("[UBUNTU API] Scan request timed out.")
        return {'status': 'failed', 'error': 'Ubuntu API request timed out', 'output_files': {}, 'api_source': 'ubuntu'}
    except requests.exceptions.RequestException as e:
        error_text = getattr(e.response, 'text', 'No response text') if e.response is not None else 'No response object'
        logging.error(f"[UBUNTU API] Scan request failed: {e}")
        logging.error(f"[UBUNTU API] Response Text: {error_text}")
        return {'status': 'failed', 'error': f"Ubuntu API error: {e}", 'response': error_text, 'output_files': {}, 'api_source': 'ubuntu'}

    # --- Process API Response (EXPECTING ZIP) ---
    logging.info("[UBUNTU API] Scan request successful (Status Code {}). Receiving results zip...".format(response.status_code))

    # Save the zip file (using the specific name)
    try:
        with open(api_zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"[UBUNTU API] Saved results zip to: {api_zip_path}")
    except Exception as e:
        logging.exception(f"[UBUNTU API] Failed to save response zip file:")
        return {'status': 'failed', 'error': f'Failed to save Ubuntu API zip: {e}', 'output_files': {}, 'api_source': 'ubuntu'}

    # --- Extract the zip file and parse summary ---
    extracted_files = {} # Stores tool_name -> absolute_path
    api_scan_status = 'completed' # Assume success unless summary indicates otherwise
    api_errors = []
    extract_target_dir = OUTPUT_DIR # Extract to the main results dir

    try:
        with zipfile.ZipFile(api_zip_path, 'r') as zip_ref:
            logging.info(f"[UBUNTU API] Extracting zip file contents to: {extract_target_dir}")
            zip_ref.extractall(extract_target_dir)
            logging.info("[UBUNTU API] Zip extraction complete.")

            # Check for scan_summary.json immediately after extraction
            summary_path = os.path.join(extract_target_dir, SCAN_SUMMARY_FILENAME)
            if not os.path.exists(summary_path):
                 logging.error(f"[UBUNTU API] Critical error: {SCAN_SUMMARY_FILENAME} not found in the extracted zip from {UBUNTU_API_URL}.")
                 # Depending on requirements, you might want to attempt to continue or fail hard.
                 # Let's return failure for now.
                 return {'status': 'failed', 'error': f'{SCAN_SUMMARY_FILENAME} missing in Ubuntu API response zip', 'output_files': {}, 'api_source': 'ubuntu'}

            # Parse the summary
            with open(summary_path, 'r') as f_summary:
                scan_summary = json.load(f_summary)
            logging.info(f"[UBUNTU API] Successfully parsed {SCAN_SUMMARY_FILENAME} from Ubuntu zip.")

            # Process summary results
            for tool_name, result_info in scan_summary.items():
                 tool_status = result_info.get('status', '').lower()
                 output_file = result_info.get('output_file') # Relative path within zip
                 reason = result_info.get('reason')

                 logging.info(f"[UBUNTU API Summary] Tool: {tool_name}, Status: {tool_status}")

                 if "completed" in tool_status and "successfully" in tool_status:
                     if output_file:
                         # Construct absolute path based on where it was extracted
                         absolute_output_path = os.path.join(extract_target_dir, output_file)
                         if os.path.exists(absolute_output_path):
                             extracted_files[tool_name] = absolute_output_path # Store absolute path
                             logging.info(f"  Output: {absolute_output_path} (Exists: True)")
                         else:
                             logging.warning(f"  [UBUNTU API] Output file listed for {tool_name} but not found after extraction: {absolute_output_path}")
                             api_scan_status = 'completed_with_errors'
                             api_errors.append(f"{tool_name}: output file missing ({absolute_output_path})")
                     else:
                         logging.warning(f"  [UBUNTU API] {tool_name} reported success but no output_file specified.")
                         api_scan_status = 'completed_with_errors'
                         api_errors.append(f"{tool_name}: no output_file provided")
                 else:
                     logging.info(f"  [UBUNTU API] Tool {tool_name} was skipped or did not complete successfully.")
                     if reason:
                         api_errors.append(f"{tool_name}: {reason}")
                     # Only mark as error if it wasn't explicitly skipped
                     if tool_status != 'skipped':
                        api_scan_status = 'completed_with_errors'

            # Optionally remove the summary file after processing if concerned about conflicts
            # try:
            #     os.remove(summary_path)
            # except OSError:
            #     logging.warning(f"[UBUNTU API] Could not remove summary file {summary_path} after processing.")


    except zipfile.BadZipFile:
        logging.error(f"[UBUNTU API] Invalid zip file received from Ubuntu API.")
        return {'status': 'failed', 'error': 'Invalid zip file received from Ubuntu API', 'output_files': {}, 'api_source': 'ubuntu'}
    except json.JSONDecodeError:
        logging.error(f"[UBUNTU API] Failed to parse {SCAN_SUMMARY_FILENAME} from Ubuntu API zip.")
        return {'status': 'failed', 'error': f'Invalid {SCAN_SUMMARY_FILENAME} from Ubuntu API', 'output_files': {}, 'api_source': 'ubuntu'}
    except FileNotFoundError as e:
         logging.error(f"[UBUNTU API] File not found during zip processing: {e}")
         return {'status': 'failed', 'error': f'File not found in Ubuntu API zip processing: {e}', 'output_files': {}, 'api_source': 'ubuntu'}
    except Exception as e:
        logging.exception(f"[UBUNTU API] Error processing zip file or summary:")
        return {'status': 'failed', 'error': f'Ubuntu API Zip/Summary processing error: {e}', 'output_files': {}, 'api_source': 'ubuntu'}

    # --- Final Result for this API call ---
    final_result = {
        'status': api_scan_status,
        'output_dir': extract_target_dir, # The directory where files were extracted
        'output_files': extracted_files, # Dict of tool -> absolute_path
        'api_source': 'ubuntu' # Add identifier
    }
    if api_errors:
        final_result['errors'] = api_errors

    logging.info(f"[UBUNTU API] Final extracted files for parsing: {list(extracted_files.keys())}")
    return final_result

# --- NEW FUNCTION for Windows API ---
def run_windows_api_scan(options):
    """
    Execute Windows API scan (Burp, ZAP) with options, expecting a zip file in return.
    Extracts the zip and parses scan_summary.json to determine results.
    """
    logging.info("[WINDOWS API] Starting Windows tools scan (Burp/ZAP)...")
    selected_tools = options.get("selected_tools", {})
    target_url = options.get("target_url") # Needed for payload

    # --- Prepare Payload for Windows API ---
    # The Windows API expects the full options relevant to Burp/ZAP
    payload = {
        "target_url": target_url,
        "selected_tools": { # Only include tools this API handles
            "use_zap": selected_tools.get("use_zap", False),
            "use_burp": selected_tools.get("use_burp", False),
        },
        # Include necessary configurations directly from the main options
        "zap_scan_policy": options.get('zap_scan_policy'),
        "zap_delay": options.get('zap_delay'),
        "zap_threads": options.get('zap_threads'),
        "zap_credentials": options.get('zap_credentials'), # Pass if present
        "burp_scan_config": options.get('burp_scan_config'),
        "burp_credentials": options.get('burp_credentials'), # Pass if present
        # Add any other general options the Windows API might need (if any)
        # e.g., "timeout": options.get("timeout")
    }
    # Remove None values from payload as the Windows API might not expect them
    payload = {k: v for k, v in payload.items() if v is not None}
    # Ensure selected_tools sub-dict is present, even if empty
    if "selected_tools" not in payload: payload["selected_tools"] = {}


    # Check if any tools are actually selected for this API before making the call
    if not payload["selected_tools"].get("use_zap") and not payload["selected_tools"].get("use_burp"):
         logging.warning("[WINDOWS API] No Windows API tools (Burp/ZAP) selected.")
         # Return skipped status, important not to make the HTTP call
         return {'status': 'skipped', 'reason': 'No Windows API tools selected', 'output_files': {}, 'api_source': 'windows'}


    logging.info(f"[WINDOWS API] Sending payload to {WINDOWS_API_URL}: {json.dumps(payload)}")

    # Ensure base output directory exists
    ensure_dir(OUTPUT_DIR)
    api_zip_path = os.path.join(OUTPUT_DIR, WINDOWS_API_ZIP_FILENAME) # Use specific name

    # --- Execute API Request ---
    response = None
    try:
        # Burp/ZAP can take a very long time. Use a significantly longer timeout.
        # 7200 seconds = 2 hours. Adjust as needed.
        response = requests.post(WINDOWS_API_URL, json=payload, headers={"Content-Type": "application/json"}, stream=True, timeout=7200)
        response.raise_for_status()

    except requests.exceptions.Timeout:
        logging.error("[WINDOWS API] Scan request timed out.")
        return {'status': 'failed', 'error': 'Windows API request timed out', 'output_files': {}, 'api_source': 'windows'}
    except requests.exceptions.RequestException as e:
        error_text = getattr(e.response, 'text', 'No response text') if e.response is not None else 'No response object'
        logging.error(f"[WINDOWS API] Scan request failed: {e}")
        logging.error(f"[WINDOWS API] Response Text: {error_text}")
        return {'status': 'failed', 'error': f"Windows API error: {e}", 'response': error_text, 'output_files': {}, 'api_source': 'windows'}

    # --- Process API Response (EXPECTING ZIP) ---
    logging.info("[WINDOWS API] Scan request successful (Status Code {}). Receiving results zip...".format(response.status_code))

    # Save the zip file
    try:
        with open(api_zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"[WINDOWS API] Saved results zip to: {api_zip_path}")
    except Exception as e:
        logging.exception(f"[WINDOWS API] Failed to save response zip file:")
        return {'status': 'failed', 'error': f'Failed to save Windows API zip: {e}', 'output_files': {}, 'api_source': 'windows'}

    # --- Extract the zip file and parse summary ---
    extracted_files = {} # Stores tool_name -> absolute_path
    api_scan_status = 'completed'
    api_errors = []
    extract_target_dir = OUTPUT_DIR # Extract to the same main results dir

    try:
        with zipfile.ZipFile(api_zip_path, 'r') as zip_ref:
            logging.info(f"[WINDOWS API] Extracting zip file contents to: {extract_target_dir}")
            zip_ref.extractall(extract_target_dir)
            logging.info("[WINDOWS API] Zip extraction complete.")

            # Check for scan_summary.json immediately after extraction
            summary_path = os.path.join(extract_target_dir, SCAN_SUMMARY_FILENAME)
            if not os.path.exists(summary_path):
                logging.error(f"[WINDOWS API] Critical error: {SCAN_SUMMARY_FILENAME} not found in the extracted zip from {WINDOWS_API_URL}.")
                return {'status': 'failed', 'error': f'{SCAN_SUMMARY_FILENAME} missing in Windows API response zip', 'output_files': {}, 'api_source': 'windows'}

            # Parse the summary
            with open(summary_path, 'r') as f_summary:
                scan_summary = json.load(f_summary)
            logging.info(f"[WINDOWS API] Successfully parsed {SCAN_SUMMARY_FILENAME} from Windows zip.")

            # Process summary results
            for tool_name, result_info in scan_summary.items():
                tool_status = result_info.get('status', '').lower()
                output_file = result_info.get('output_file') # Relative path within zip
                reason = result_info.get('reason')

                logging.info(f"[WINDOWS API Summary] Tool: {tool_name}, Status: {tool_status}")

                if "completed" in tool_status and "successfully" in tool_status:
                    if output_file:
                        # Construct absolute path based on where it was extracted
                        absolute_output_path = os.path.join(extract_target_dir, output_file)
                        if os.path.exists(absolute_output_path):
                            extracted_files[tool_name] = absolute_output_path # Store absolute path
                            logging.info(f"  Output: {absolute_output_path} (Exists: True)")
                        else:
                            logging.warning(f"  [WINDOWS API] Output file listed for {tool_name} but not found after extraction: {absolute_output_path}")
                            api_scan_status = 'completed_with_errors'
                            api_errors.append(f"{tool_name}: output file missing ({absolute_output_path})")
                    else:
                        logging.warning(f"  [WINDOWS API] {tool_name} reported success but no output_file specified.")
                        api_scan_status = 'completed_with_errors'
                        api_errors.append(f"{tool_name}: no output_file provided")
                else:
                    logging.info(f"  [WINDOWS API] Tool {tool_name} was skipped or did not complete successfully.")
                    if reason:
                        api_errors.append(f"{tool_name}: {reason}")
                    if tool_status != 'skipped':
                        api_scan_status = 'completed_with_errors'

            # Optionally remove the summary file after processing
            # try:
            #     os.remove(summary_path)
            # except OSError:
            #     logging.warning(f"[WINDOWS API] Could not remove summary file {summary_path} after processing.")


    except zipfile.BadZipFile:
        logging.error(f"[WINDOWS API] Invalid zip file received from Windows API.")
        return {'status': 'failed', 'error': 'Invalid zip file received from Windows API', 'output_files': {}, 'api_source': 'windows'}
    except json.JSONDecodeError:
        logging.error(f"[WINDOWS API] Failed to parse {SCAN_SUMMARY_FILENAME} from Windows API zip.")
        return {'status': 'failed', 'error': f'Invalid {SCAN_SUMMARY_FILENAME} from Windows API', 'output_files': {}, 'api_source': 'windows'}
    except FileNotFoundError as e:
         logging.error(f"[WINDOWS API] File not found during zip processing: {e}")
         return {'status': 'failed', 'error': f'File not found in Windows API zip processing: {e}', 'output_files': {}, 'api_source': 'windows'}
    except Exception as e:
        logging.exception(f"[WINDOWS API] Error processing zip file or summary:")
        return {'status': 'failed', 'error': f'Windows API Zip/Summary processing error: {e}', 'output_files': {}, 'api_source': 'windows'}

    # --- Final Result for this API call ---
    final_result = {
        'status': api_scan_status,
        'output_dir': extract_target_dir,
        'output_files': extracted_files, # Dict of tool -> absolute_path
        'api_source': 'windows' # Add identifier
    }
    if api_errors:
        final_result['errors'] = api_errors

    logging.info(f"[WINDOWS API] Final extracted files for parsing: {list(extracted_files.keys())}")
    return final_result


# --- Parsing and Combining Functions ---

# MODIFIED: Accepts a dictionary of successful outputs directly
def run_parsers(all_successful_output_files):
    """Runs the necessary parsers on the generated scan output files."""
    logging.info("=== Running Parsers ===")
    ensure_dir(VULN_DIR)
    parser_success = True
    any_parser_run = False

    # Define parser mappings: tool_name -> (parser_script, output_suffix)
    parser_map = {
        "zap": ("zap_parser.py", "vulnerabilities_zap.json"),
        "burp": ("burp_parser.py", "vulnerabilities_burp.json"),
        "wapiti": ("wapiti_parser.py", "vulnerabilities_wapiti.json"),
        "nuclei": ("nuclei_parser.py", "vulnerabilities_nuclei.json"),
        "nikto": ("nikto_parser.py", "vulnerabilities_nikto.json"),
        "whatweb": ("whatweb_parser.py", "vulnerabilities_whatweb.json"),
        "wafw00f": ("wafw00f_parser.py", "vulnerabilities_wafw00f.json"),
    }

    # Use the dictionary passed directly
    if not all_successful_output_files:
        logging.warning("No successful scan outputs found to parse.")
        return True # Not a failure if there was nothing to parse

    logging.info(f"Attempting to parse files for tools: {list(all_successful_output_files.keys())}")

    for tool, (parser_script, output_suffix) in parser_map.items():
        # Check if the tool exists as a key in the successful outputs dict
        if tool in all_successful_output_files:
            input_file = all_successful_output_files[tool] # Get the absolute path
            parser_path = os.path.join(PARSERS_DIR, parser_script)
            output_file = os.path.join(VULN_DIR, output_suffix) # Where parser should write

            # Ensure input file and parser script exist before attempting to run
            if os.path.exists(input_file) and os.path.exists(parser_path):
                logging.info(f"Running parser: {parser_script} on {input_file}")
                any_parser_run = True
                try:
                    # Use absolute paths for parser arguments
                    cmd = [sys.executable, parser_path, input_file, output_file] # Use sys.executable
                    process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
                    logging.info(f"Parser {parser_script} stdout:\n{process.stdout}")
                    if process.stderr:
                        logging.warning(f"Parser {parser_script} stderr:\n{process.stderr}")
                    # Verify output file creation
                    if not os.path.exists(output_file):
                        logging.error(f"Parser {parser_script} ran but output file {output_file} not found!")
                        parser_success = False

                except subprocess.CalledProcessError as e:
                    logging.error(f"Error running parser {parser_script} on {input_file}: {e}")
                    logging.error(f"Stderr: {e.stderr}")
                    parser_success = False
                except subprocess.TimeoutExpired:
                    logging.error(f"Parser {parser_script} timed out on {input_file}.")
                    parser_success = False
                except Exception as e:
                    logging.exception(f"Unexpected error running parser {parser_script} on {input_file}:")
                    parser_success = False
            elif not os.path.exists(input_file):
                # This indicates an issue with the previous step storing the path
                logging.error(f"Input file {input_file} for parser {parser_script} not found, though it was expected. Skipping.")
                parser_success = False # Treat this as an error
            elif not os.path.exists(parser_path):
                logging.error(f"Parser script {parser_path} not found. Cannot parse {tool} results.")
                parser_success = False # Indicate failure if parser script is missing
        # else: tool not found in successful outputs, so skip parsing it.

    if not any_parser_run and all_successful_output_files:
         logging.warning("Scan outputs were found, but no corresponding parsers were configured or available to run.")
         # This isn't necessarily a failure of the parsing *step*, but maybe worth noting.

    if not parser_success:
        logging.error("One or more parsers failed to execute correctly.")

    return parser_success


def run_combiner():
    """Runs the combine.py script."""
    logging.info("=== Running Combiner ===")
    combiner_script = os.path.join(COMBINE_DIR, "combine.py")

    # Ensure vulnerability directory exists before checking contents
    ensure_dir(VULN_DIR)

    # Check if there are any vulnerability files to combine
    try:
        vuln_files_exist = any(f.startswith('vulnerabilities_') and f.endswith('.json') for f in os.listdir(VULN_DIR))
    except FileNotFoundError:
        logging.error(f"Vulnerability directory {VULN_DIR} not found. Cannot run combiner.")
        return False
    except Exception as e:
        logging.error(f"Error listing files in {VULN_DIR}: {e}")
        return False


    if not vuln_files_exist:
        logging.warning(f"No vulnerability files found in {VULN_DIR} to combine. Skipping combiner.")
        # Create an empty final report to signify completion
        try:
             with open(FINAL_REPORT_PATH, 'w') as f:
                 json.dump([], f)
             logging.info("Created empty final report as no vulnerabilities were parsed.")
             return True
        except Exception as e:
             logging.error(f"Failed to create empty final report: {e}")
             return False # Failed to create the empty file

    if not os.path.exists(combiner_script):
        logging.error(f"Combiner script not found at {combiner_script}")
        return False

    try:
        # Run combine.py from the COMBINE_DIR so its relative paths work
        process = subprocess.run(
            [sys.executable, os.path.basename(combiner_script)], # Run script by name using sys.executable
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

# --- Main Execution Logic (MODIFIED) ---

def main(options_data):
    """Main function accepting options dictionary, orchestrates API calls"""
    ensure_dir(OUTPUT_DIR)
    ensure_dir(COMBINE_DIR)
    ensure_dir(VULN_DIR)

    selected_tools = options_data.get("selected_tools", {})
    target_url = options_data.get('target_url')

    if not target_url:
         logging.error("Mandatory field 'target_url' is missing in options.")
         print(json.dumps({"status": "missing_target_url"})) # Use json.dumps for consistency
         return

    # --- Determine which tools go to which API ---
    ubuntu_tools_selected = any(selected_tools.get(tool) for tool in ["use_wapiti", "use_nuclei", "use_nikto", "use_wafw00f", "use_whatweb"])
    windows_tools_selected = any(selected_tools.get(tool) for tool in ["use_zap", "use_burp"])

    if not (ubuntu_tools_selected or windows_tools_selected):
        logging.warning("No tools selected for scanning.")
        print(json.dumps({"status": "no_tools_selected"}))
        return

    logging.info("=== Starting All Selected Scans via APIs ===")

    # --- Execute scans concurrently via APIs ---
    scan_results = [] # This will hold result dictionaries from BOTH APIs
    with ThreadPoolExecutor(max_workers=2) as executor: # Max workers = number of APIs
        futures = []

        # Submit task for Ubuntu API if needed
        if ubuntu_tools_selected:
            # Pass the full options_data, the function will generate relevant commands
            futures.append(executor.submit(run_ubuntu_api_scan, options_data))
            logging.info("Submitted task for Ubuntu API tools.")

        # Submit task for Windows API if needed
        if windows_tools_selected:
            # Pass the full options_data, the function will construct the payload
            futures.append(executor.submit(run_windows_api_scan, options_data))
            logging.info("Submitted task for Windows API tools (Burp/ZAP).")

        # Collect results from completed futures
        for future in futures:
            try:
                result = future.result() # Get the dictionary returned by the API function
                scan_results.append(result)
            except Exception as exc:
                # This catches errors in the future execution itself (rare)
                logging.exception(f'API Scan task generated an unexpected exception:')
                # Add a generic error marker; specific API function should log details
                scan_results.append({'status': 'error', 'error': f'API Future result exception: {exc}', 'output_files': {}, 'api_source': 'unknown'})

    # --- Report Scan Results (Consolidated) ---
    logging.info("\n=== API Scan Execution Summary ===")
    any_scan_failed = False
    any_scan_completed_with_output = False # Track if at least one scan produced usable output files
    all_output_files = {} # Collect all successful outputs (tool_name -> absolute_path)

    for result in scan_results:
        status = result.get('status', 'unknown')
        api_source = result.get('api_source', 'unknown').upper()
        # Identify tools from output_files keys if possible, otherwise use API source
        tool_names_in_result = list(result.get('output_files', {}).keys())
        task_description = f"{api_source} API Call"
        if tool_names_in_result:
             task_description += f" (Tools: {', '.join(tool_names_in_result)})"
        elif status == 'skipped':
             task_description += f" (Reason: {result.get('reason', 'N/A')})"

        logging.info(f"[{task_description}]: Status: {status}")

        if status in ['completed', 'succeeded', 'completed_with_errors']:
             # Check if there are actual output files generated
             if result.get('output_files'):
                  any_scan_completed_with_output = True
                  # Add successfully generated files to the combined dictionary
                  # This assumes tool names (keys) are unique across APIs
                  all_output_files.update(result.get('output_files', {}))
                  logging.info(f"  Successfully processed outputs: {list(result.get('output_files', {}).keys())}")
             else:
                  # Completed but no output files? Log warning.
                  logging.warning(f"  Task reported completion but had no output files.")

             # Log specific errors reported within the task (e.g., from summary parsing)
             if 'errors' in result and result['errors']:
                 logging.warning(f"  Reported errors within task: {result['errors']}")
             # If status is 'completed_with_errors', we still proceed but log it.

        elif status == 'skipped':
              # Already logged reason in task_description
              logging.info(f"  Task skipped.")
        else: # failure, error, config_error, timeout etc.
             logging.error(f"  Task Failed/Error. Message: {result.get('error', 'Unknown error')}")
             any_scan_failed = True # Mark that at least one critical step failed

    # --- Decide whether to proceed to Parsing ---
    if any_scan_failed:
        logging.error("One or more critical API scan tasks failed. Aborting further processing.")
        print(json.dumps({"status": "scan_failed"}))
        return

    # Check if we actually got any files to parse
    if not any_scan_completed_with_output or not all_output_files:
         logging.warning("No API scan tasks completed successfully or produced output files. Skipping parsing and combining.")
         # Decide on final status: success (empty report) or failure?
         # Let's create an empty report for consistency.
         combiner_ok = run_combiner() # Run combiner to create empty report
         if combiner_ok:
             print(json.dumps({"status": "success", "report_path": FINAL_REPORT_PATH, "message": "No tools produced output."}))
         else:
              print(json.dumps({"status": "combining_failed", "error": "Failed to create empty final report."}))
         return

    # --- Run Parsers ---
    logging.info("Proceeding to parsing stage with collected files.")
    parsers_ok = run_parsers(all_output_files) # Pass the combined dictionary
    if not parsers_ok:
        logging.error("Parsing failed. Skipping combining.")
        print(json.dumps({"status": "parsing_failed"}))
        return

    # --- Run Combiner --- (No changes needed in the call)
    logging.info("Proceeding to combining stage.")
    combiner_ok = run_combiner()
    if not combiner_ok:
        logging.error("Combining failed.")
        print(json.dumps({"status": "combining_failed"}))
        return

    # --- Final Success ---
    logging.info("=== Processing Pipeline Completed Successfully ===")
    final_report_content = []
    try:
         if os.path.exists(FINAL_REPORT_PATH):
              with open(FINAL_REPORT_PATH, 'r') as f:
                  final_report_content = json.load(f)
    except Exception as e:
         logging.warning(f"Could not read final report content after creation: {e}") # Not fatal

    alert_count = len(final_report_content) if isinstance(final_report_content, list) else 0
    logging.info(f"Final report contains {alert_count} alerts.")
    print(json.dumps({"status": "success", "report_path": FINAL_REPORT_PATH}))


# --- Command Line Execution ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py '<json_options_string>'")
        print("Example: python main.py '{\"target_url\": \"http://example.com\", \"selected_tools\": {\"use_zap\": true, \"use_nuclei\": true}}'")
        sys.exit(1)

    json_options_string = sys.argv[1]
    try:
        options = json.loads(json_options_string)
        logging.info("Successfully parsed options JSON from command line.")

        # Basic validation
        if not isinstance(options.get("selected_tools"), dict):
             raise ValueError("Missing or invalid 'selected_tools' dictionary in options.")
        if not options.get("target_url"):
             # Check target_url here before calling main
             raise ValueError("Missing mandatory 'target_url' in options.")

        main(options) # Pass the dictionary directly

    except json.JSONDecodeError:
        logging.error("Error: Invalid JSON string provided as argument.")
        print(json.dumps({"status": "invalid_json_input"}))
        sys.exit(1)
    except ValueError as ve: # Catch specific validation errors
         logging.error(f"Error: Invalid options provided: {ve}")
         # Ensure error message is properly escaped for JSON
         error_msg = str(ve).replace('"', '\\"')
         print(json.dumps({"status": "invalid_options", "error": error_msg}))
         sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred during execution:")
        # Ensure error message is properly escaped for JSON
        error_msg = str(e).replace('"', '\\"')
        print(json.dumps({"status": "runtime_error", "error": error_msg}))
        sys.exit(1)
