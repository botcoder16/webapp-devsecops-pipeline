import sys
import json
import subprocess # Added for running parsers/combine
import os
import zipfile # Added for zip extraction
import io      # Added for handling zip in memory if needed, but file better
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

API_URL = "http://192.168.111.134:5000/scan" # Adjust if needed
API_ZIP_FILENAME = "api_scan_results.zip" # Name for the received zip
SCAN_SUMMARY_FILENAME = "scan_summary.json" # Expected summary file in the zip

# --- Helper Function ---
def ensure_dir(directory_path):
    """Creates a directory if it doesn't exist."""
    os.makedirs(directory_path, exist_ok=True)


# --- Scan Execution Functions (Modified for consistent output paths) ---

def run_api_scan(options):
    """
    Execute API scan with options, expecting a zip file in return.
    Extracts the zip and parses scan_summary.json to determine results.
    """
    try:
        logging.info("[API] Starting API tools scan...")
        selected_tools = options.get("selected_tools", {})
        commands = {}
        requested_api_tools = [] # Keep track of tools we asked the API to run

        # Ensure base output directory exists
        ensure_dir(OUTPUT_DIR)
        api_zip_path = os.path.join(OUTPUT_DIR, API_ZIP_FILENAME)

        # --- Generate Commands (Paths are now less critical here, as summary dictates final path) ---
        # We still generate commands, but primarily to tell the *server* what to run.
        # The *client* will rely on scan_summary.json for actual output paths later.
        if selected_tools.get("use_nuclei"):
            commands["nuclei"] = generate_nuclei_command(options)
            requested_api_tools.append("nuclei")
            logging.info(f"[API] Generated Nuclei command") # Command details logged by server

        if selected_tools.get("use_wapiti"):
            commands["wapiti"] = generate_wapiti_command(options)
            requested_api_tools.append("wapiti")
            logging.info(f"[API] Generated Wapiti command")

        if selected_tools.get("use_nikto"):
            commands["nikto"] = generate_nikto_command(options)
            requested_api_tools.append("nikto")
            logging.info(f"[API] Generated Nikto command")

        if selected_tools.get("use_wafw00f"):
            commands["wafw00f"] = generate_wafw00f_command(options)
            requested_api_tools.append("wafw00f")
            logging.info(f"[API] Generated Wafw00f command")

        if selected_tools.get("use_whatweb"):
            commands["whatweb"] = generate_whatweb_command(options)
            requested_api_tools.append("whatweb")
            logging.info(f"[API] Generated WhatWeb command")


        if not commands:
            logging.warning("[API] No API tools selected or commands generated.")
            return {'status': 'skipped', 'reason': 'No API tools selected', 'output_files': {}}

        payload = {"commands": commands}
        logging.info(f"[API] Sending payload to API for tools: {list(commands.keys())}")

        # --- Execute API Request ---
        response = None # Initialize response
        try:
            response = requests.post(API_URL, json=payload, headers={"Content-Type": "application/json"}, stream=True) # Use stream=True for zip, adjust timeout
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        except requests.exceptions.Timeout:
            logging.error("[API] Scan request timed out.")
            return {'status': 'failed', 'error': 'API request timed out', 'output_files': {}}
        except requests.exceptions.RequestException as e:
            error_text = getattr(e.response, 'text', 'No response text') if e.response is not None else 'No response object'
            logging.error(f"[API] Scan request failed: {e}")
            logging.error(f"[API] Response Text: {error_text}")
            return {'status': 'failed', 'error': f"API error: {e}", 'response': error_text, 'output_files': {}}

        # --- Process API Response (EXPECTING ZIP) ---
        logging.info("[API] Scan request successful (Status Code {}). Receiving results zip...".format(response.status_code))

        # Save the zip file
        try:
            with open(api_zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logging.info(f"[API] Saved results zip to: {api_zip_path}")
        except Exception as e:
            logging.exception(f"[API] Failed to save response zip file:")
            return {'status': 'failed', 'error': f'Failed to save zip: {e}', 'output_files': {}}

        # Extract the zip file and parse summary
        extracted_files = {}
        api_scan_status = 'completed' # Assume success unless summary indicates otherwise
        api_errors = []

        try:
            with zipfile.ZipFile(api_zip_path, 'r') as zip_ref:
                logging.info(f"[API] Extracting zip file contents to: {OUTPUT_DIR}")
                zip_ref.extractall(OUTPUT_DIR)
                logging.info("[API] Zip extraction complete.")

                # Check for scan_summary.json
                summary_path = os.path.join(OUTPUT_DIR, SCAN_SUMMARY_FILENAME)
                if not os.path.exists(summary_path):
                    logging.error(f"[API] Critical error: {SCAN_SUMMARY_FILENAME} not found in the extracted zip.")
                    return {'status': 'failed', 'error': f'{SCAN_SUMMARY_FILENAME} missing in API response zip', 'output_files': {}}

                # Parse the summary
                with open(summary_path, 'r') as f_summary:
                    scan_summary = json.load(f_summary)
                logging.info(f"[API] Successfully parsed {SCAN_SUMMARY_FILENAME}")

                # Process summary results
                # --- Inside the zip summary parsing logic ---
                for tool_name, result_info in scan_summary.items():
                    tool_status = result_info.get('status', '').lower()
                    output_file = result_info.get('output_file')
                    reason = result_info.get('reason')

                    logging.info(f"[API Summary] Tool: {tool_name}, Status: {tool_status}")

                    # Check if the tool completed successfully
                    if "completed" in tool_status and "successfully" in tool_status:
                        if output_file:
                            absolute_output_path = os.path.join(OUTPUT_DIR, output_file) \
                                if not os.path.isabs(output_file) else output_file

                            if os.path.exists(absolute_output_path):
                                extracted_files[tool_name] = absolute_output_path
                                logging.info(f"  Output: {absolute_output_path} (Exists: True)")
                            else:
                                logging.warning(f"  Output file listed for {tool_name} but not found: {absolute_output_path}")
                                api_scan_status = 'completed_with_errors'
                                api_errors.append(f"{tool_name}: output file missing ({absolute_output_path})")
                        else:
                            logging.warning(f"  {tool_name} reported success but no output_file specified.")
                            api_scan_status = 'completed_with_errors'
                            api_errors.append(f"{tool_name}: no output_file provided")
                    else:
                        logging.info(f"  Tool {tool_name} was skipped or did not complete successfully.")
                        if reason:
                            api_errors.append(f"{tool_name}: {reason}")
                        api_scan_status = 'completed_with_errors'
                        
                        
        except zipfile.BadZipFile:
            logging.error(f"[API] Invalid zip file received from API.")
            return {'status': 'failed', 'error': 'Invalid zip file received', 'output_files': {}}
        except json.JSONDecodeError:
            logging.error(f"[API] Failed to parse {SCAN_SUMMARY_FILENAME}.")
            return {'status': 'failed', 'error': f'Invalid {SCAN_SUMMARY_FILENAME}', 'output_files': {}}
        except FileNotFoundError as e:
             logging.error(f"[API] File not found during zip processing: {e}")
             return {'status': 'failed', 'error': f'File not found: {e}', 'output_files': {}}
        except Exception as e:
            logging.exception(f"[API] Error processing zip file or summary:")
            return {'status': 'failed', 'error': f'Zip/Summary processing error: {e}', 'output_files': {}}

        # --- Final Result ---
        # Clean up the zip file? Optional.
        # try:
        #     os.remove(api_zip_path)
        #     logging.info(f"[API] Removed temporary zip file: {api_zip_path}")
        # except OSError as e:
        #     logging.warning(f"[API] Could not remove temporary zip file {api_zip_path}: {e}")


        final_result = {
            'status': api_scan_status,
            'output_dir': OUTPUT_DIR,
            'output_files': extracted_files,
        }

        if api_errors:
            final_result['errors'] = api_errors

        logging.info(f"[API] Final extracted files for parsing: {list(extracted_files.keys())}")
        return final_result


    except Exception as e:
        logging.exception("[API] Unexpected error during API scan initiation or processing:") # Log full traceback
        return {'status': 'error', 'error': str(e), 'output_files': {}} # Return empty output_files on major error


def run_zap_scan(zap_config):
    """Execute ZAP scan with configuration derived from input JSON"""
    try:
        logging.info("[ZAP] Starting ZAP scan...")
        if not zap_config or 'target_url' not in zap_config or not zap_config['target_url']:
            logging.error("[ZAP] Insufficient ZAP configuration provided (target_url missing or empty).")
            return {'status': 'failed', 'error': 'Insufficient ZAP configuration (target_url missing)'}
        if 'report_path' not in zap_config or not zap_config['report_path']:
             logging.error("[ZAP] ZAP report path not configured.")
             return {'status': 'failed', 'error': 'ZAP report_path missing'}

        # Ensure output directory exists
        ensure_dir(os.path.dirname(zap_config['report_path']))
        logging.info(f"[ZAP] Report will be saved to: {zap_config['report_path']}")

        result = execute_zap_scan(zap_config) # execute_zap_scan needs zap_config dict

        # Add the output file path to the result for consistency
        if result.get('status') == 'completed':
            result['output_files'] = {'zap': zap_config['report_path']}
            logging.info(f"[ZAP] Scan completed. Report: {zap_config['report_path']}")
        else:
            result['output_files'] = {}
            logging.error(f"[ZAP] Scan failed or did not complete. Status: {result.get('status')}, Error: {result.get('error')}")


        return result

    except Exception as e:
        logging.exception("[ZAP] Error during ZAP scan:")
        return {'status': 'error', 'error': str(e), 'output_files': {}}

def run_burp_scan(burp_config):
    """Execute Burp scan with configuration derived from input JSON"""
    try:
        logging.info("[BURP] Starting Burp scan...")
        if not burp_config or 'target_url' not in burp_config or not burp_config['target_url']:
            logging.error("[BURP] Insufficient Burp configuration provided (target_url missing or empty).")
            return {'status': 'failed', 'error': 'Insufficient Burp configuration (target_url missing)'}
        if 'report_path' not in burp_config or not burp_config['report_path']:
             logging.error("[BURP] Burp report path not configured.")
             return {'status': 'failed', 'error': 'Burp report_path missing'}


        # Ensure output directory exists
        ensure_dir(os.path.dirname(burp_config['report_path']))
        logging.info(f"[BURP] Report will be saved to: {burp_config['report_path']}")

        result = execute_burp_scan(burp_config) # execute_burp_scan needs burp_config dict

        # Add the output file path to the result for consistency
        if result.get('status') == 'completed':
            result['output_files'] = {'burp': burp_config['report_path']}
            logging.info(f"[BURP] Scan completed. Report: {burp_config['report_path']}")
        else:
            result['output_files'] = {}
            logging.error(f"[BURP] Scan failed or did not complete. Status: {result.get('status')}, Error: {result.get('error')}")

        return result

    except Exception as e:
        logging.exception("[BURP] Error during Burp scan:")
        return {'status': 'error', 'error': str(e), 'output_files': {}}


# --- NEW: Parsing and Combining Functions ---
# (No changes needed in run_parsers or run_combiner itself,
# as they rely on the 'output_files' dictionary being correctly
# populated by the run_*_scan functions based on scan success)

def run_parsers(scan_results):
    """Runs the necessary parsers on the generated scan output files."""
    logging.info("=== Running Parsers ===")
    ensure_dir(VULN_DIR)
    parser_success = True
    any_parser_run = False

    # Define parser mappings: tool_name -> (parser_script, input_suffix_ignored, output_suffix)
    # Input suffix isn't strictly needed anymore as we use the exact path from scan_results
    parser_map = {
        "zap": ("zap_parser.py", "vulnerabilities_zap.json"),
        "burp": ("burp_parser.py", "vulnerabilities_burp.json"),
        "wapiti": ("wapiti_parser.py", "vulnerabilities_wapiti.json"),
        "nuclei": ("nuclei_parser.py", "vulnerabilities_nuclei.json"),
         # Add other parsers here if needed (e.g., nikto, whatweb)
        "nikto": ("nikto_parser.py", "vulnerabilities_nikto.json"), # Example
        "whatweb": ("whatweb_parser.py", "vulnerabilities_whatweb.json"), # Example
        "wafw00f": ("wafw00f_parser.py", "vulnerabilities_wafw00f.json"), # Example
    }

    all_successful_output_files = {}
    for result in scan_results:
        # Only consider results from completed scans that might have output files
        if result.get('status') in ['completed', 'completed_with_errors', 'succeeded'] and result.get('output_files'):
            all_successful_output_files.update(result.get('output_files', {}))

    if not all_successful_output_files:
        logging.warning("No successful scan outputs found to parse.")
        return True # Not a failure if there was nothing to parse

    logging.info(f"Attempting to parse files: {all_successful_output_files}")

    for tool, (parser_script, output_suffix) in parser_map.items():
        if tool in all_successful_output_files:
            input_file = all_successful_output_files[tool] # Get the exact path
            parser_path = os.path.join(PARSERS_DIR, parser_script)
            output_file = os.path.join(VULN_DIR, output_suffix)

            if os.path.exists(input_file) and os.path.exists(parser_path):
                logging.info(f"Running parser: {parser_script} on {input_file}")
                any_parser_run = True
                try:
                    # Use absolute paths for parser arguments
                    cmd = ["python", parser_path, input_file, output_file]
                    # Assumes parsers accept: script.py <input_file> <output_file>
                    process = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120) # Increased timeout slightly
                    logging.info(f"Parser {parser_script} output:\n{process.stdout}")
                    if process.stderr:
                        logging.warning(f"Parser {parser_script} stderr:\n{process.stderr}")
                    if not os.path.exists(output_file):
                        logging.error(f"Parser {parser_script} ran but output file {output_file} not found!")
                        parser_success = False # This specific parser failed

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
                # This case should be less likely now if all_successful_output_files is accurate
                logging.warning(f"Input file {input_file} for parser {parser_script} not found, though it was expected. Skipping.")
                # Optionally mark as error? Depends on strictness.
                # parser_success = False
            elif not os.path.exists(parser_path):
                logging.error(f"Parser script {parser_path} not found. Cannot parse {tool} results.")
                parser_success = False # Indicate failure if parser script is missing
        # Don't log "skipping" for tools that weren't successful or didn't produce output


    if not any_parser_run and all_successful_output_files:
         logging.warning("Scan outputs were found, but no corresponding parsers were configured or available.")
         # This isn't necessarily a failure of the parsing *step*, but maybe worth noting.

    if not parser_success:
        logging.error("One or more parsers failed to execute correctly.")

    return parser_success


def run_combiner():
    """Runs the combine.py script."""
    logging.info("=== Running Combiner ===")
    combiner_script = os.path.join(COMBINE_DIR, "combine.py")
    # Check if there are any vulnerability files to combine
    vuln_files_exist = any(f.startswith('vulnerabilities_') and f.endswith('.json') for f in os.listdir(VULN_DIR))

    if not vuln_files_exist:
        logging.warning(f"No vulnerability files found in {VULN_DIR}. Skipping combiner.")
        # Create an empty final report to signify completion? Or return success? Let's return success.
        # Or maybe create an empty JSON array in final_alerts.json
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
            ["python", os.path.basename(combiner_script)], # Run script by name
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
    ensure_dir(COMBINE_DIR) # Ensure combine dir exists
    ensure_dir(VULN_DIR) # Ensure vuln dir exists (for parsers)


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
    target_url = options_data.get('target_url')

    if not target_url:
         logging.error("Mandatory field 'target_url' is missing in options.")
         print("{\"status\": \"missing_target_url\"}")
         return

    # Construct zap_config if ZAP is selected
    if use_zap:
        zap_output_path = os.path.join(OUTPUT_DIR, 'zap_scan.json')
        # Ensure the specific subdirectory for ZAP exists
        ensure_dir(os.path.dirname(zap_output_path))
        zap_config = {
            'target_url': target_url,
            'scan_policy': options_data.get('zap_scan_policy', 'Default Policy'),
            'delay_in_ms': int(options_data.get('zap_delay', 100)),
            'threads_per_host': int(options_data.get('zap_threads', 5)),
            'credentials': options_data.get('zap_credentials'), # Will be None if not provided
            'report_path': zap_output_path # Use absolute path
        }
        logging.info(f"ZAP Config prepared for: {zap_config.get('target_url')}")


    # Construct burp_config if Burp is selected
    if use_burp:
        burp_output_path = os.path.join(OUTPUT_DIR, 'burp_scan.json')
        # Ensure the specific subdirectory for Burp exists
        ensure_dir(os.path.dirname(burp_output_path))
        burp_config = {
            'target_url': target_url,
            'scan_config': { # Use the nested structure expected by burp scanner
                 "name": options_data.get('burp_scan_config', 'Crawl and Audit - Balanced'),
                 "type": "NamedConfiguration"
            },
            'credentials': options_data.get('burp_credentials'), # Will be None if not provided
            'report_path': burp_output_path # Use absolute path
        }
        logging.info(f"Burp Config prepared for: {burp_config.get('target_url')}")


    # --- Execute scans concurrently ---
    scan_results = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        if use_api_tools and api_options:
            futures.append(executor.submit(run_api_scan, api_options))
        if use_zap:
            # Validate config slightly before submitting
            if zap_config.get('target_url') and zap_config.get('report_path'):
                futures.append(executor.submit(run_zap_scan, zap_config))
            else:
                logging.error("Skipping ZAP execution due to configuration errors.")
                scan_results.append({'status': 'config_error', 'error': 'ZAP config invalid', 'output_files': {}})
        if use_burp:
             # Validate config slightly before submitting
            if burp_config.get('target_url') and burp_config.get('report_path'):
                futures.append(executor.submit(run_burp_scan, burp_config))
            else:
                 logging.error("Skipping Burp execution due to configuration errors.")
                 scan_results.append({'status': 'config_error', 'error': 'Burp config invalid', 'output_files': {}})


        # Collect results
        for future in futures:
            try:
                result = future.result()
                scan_results.append(result)
            except Exception as exc:
                logging.exception(f'Scan task generated an exception:') # Log full traceback
                scan_results.append({'status': 'error', 'error': f'Future result exception: {exc}', 'output_files': {}})


    # --- Report Scan Results ---
    logging.info("\n=== Scan Execution Summary ===")
    any_scan_failed = False # Track if *any* scan step reported failure/error
    any_scan_completed = False # Track if at least one scan produced usable results

    for result in scan_results:
        status = result.get('status', 'unknown')
        tool_name = "Unknown Scan Task"
        # Determine tool name based on keys in output_files or other markers
        if 'output_files' in result and result['output_files']:
             keys = list(result['output_files'].keys())
             if len(keys) == 1:
                 tool_name = keys[0].capitalize() + " Scan"
             else: # Likely the API scan result with multiple files
                 tool_name = "API Scan"
        elif 'alerts_count' in result: tool_name = "ZAP Scan" # ZAP might not have output_files on failure
        elif 'issues_count' in result: tool_name = "Burp Scan" # Burp might not have output_files on failure
        elif 'reason' in result and 'No API tools selected' in result['reason']: tool_name = "API Scan (Skipped)"
        elif status == 'config_error': tool_name = "Scan Config Error" # Generic for config issues before running


        logging.info(f"[{tool_name}]: Status: {status}")

        # Check for success/completion
        if status in ['completed', 'succeeded', 'completed_with_errors']:
             any_scan_completed = True
             logging.info(f"  Successfully processed outputs: {result.get('output_files', 'N/A')}")
             if 'errors' in result: # Specific errors reported by API summary
                 logging.warning(f"  Reported errors within task: {result['errors']}")
             # If status is 'completed_with_errors', we might still proceed but log it.
        elif status == 'skipped':
              logging.warning(f"  Scan skipped. Reason: {result.get('reason', 'Not specified')}")
        else: # failure, error, config_error, timeout etc.
             logging.error(f"  Task Failed/Error. Message: {result.get('error', 'Unknown error')}")
             any_scan_failed = True # Mark that at least one scan failed

    # --- Decide whether to proceed ---
    if any_scan_failed:
        logging.error("One or more scan tasks failed or encountered errors. Aborting further processing.")
        print("{\"status\": \"scan_failed\"}") # Output JSON status
        return # Exit if critical scans failed

    if not any_scan_completed:
         logging.warning("No scan tasks completed successfully or produced results (might have been skipped or had config errors). Skipping parsing and combining.")
         # Consider if this should be a 'success' or 'scan_failed'. Let's treat it as non-failure for now, maybe resulting in empty report.
         print("{\"status\": \"no_scans_completed\"}")
         return

    # --- Run Parsers ---
    logging.info("Proceeding to parsing stage.")
    parsers_ok = run_parsers(scan_results) # Pass all results, parser will filter based on success/output_files
    if not parsers_ok:
        logging.error("Parsing failed. Skipping combining.")
        print("{\"status\": \"parsing_failed\"}") # Output JSON status
        return # Exit if parsing failed

    # --- Run Combiner ---
    logging.info("Proceeding to combining stage.")
    combiner_ok = run_combiner()
    if not combiner_ok:
        logging.error("Combining failed.")
        print("{\"status\": \"combining_failed\"}") # Output JSON status
        return # Exit if combining failed

    # --- Final Success ---
    logging.info("=== Processing Pipeline Completed Successfully ===")
    # Check if the final report actually has content (combiner might create empty if no vulns)
    final_report_content = []
    try:
         if os.path.exists(FINAL_REPORT_PATH):
              with open(FINAL_REPORT_PATH, 'r') as f:
                  final_report_content = json.load(f)
    except Exception:
         logging.warning("Could not read final report content after creation.") # Not fatal

    logging.info(f"Final report contains {len(final_report_content)} alerts.")
    print(json.dumps({"status": "success", "report_path": FINAL_REPORT_PATH})) # Output JSON status


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

        # Basic validation of options needed by main logic
        if not isinstance(options.get("selected_tools"), dict):
             raise ValueError("Missing or invalid 'selected_tools' dictionary in options.")
        # target_url checked within main() now

        main(options) # Pass the dictionary directly

    except json.JSONDecodeError:
        logging.error("Error: Invalid JSON string provided as argument.")
        print("{\"status\": \"invalid_json_input\"}")
        sys.exit(1)
    except ValueError as ve: # Catch specific validation errors
         logging.error(f"Error: Invalid options provided: {ve}")
         print(f"{{\"status\": \"invalid_options\", \"error\": \"{str(ve)}\"}}")
         sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred during execution:") # Log full traceback
        # Try to format error for JSON output, escaping quotes
        error_str = str(e).replace('"', '\\"')
        print(f"{{\"status\": \"runtime_error\", \"error\": \"{error_str}\"}}")
        sys.exit(1)