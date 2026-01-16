import logging
import sys
from flask import Flask, request, jsonify, send_file
import subprocess
import os
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import zipfile
import io

# ------------------------------
# Logging Configuration
# ------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("scanner_server.log") # Make sure this path is writable
    ]
)
logger = logging.getLogger(__name__)

# ------------------------------
# Flask App and Tool Paths (Assuming these are correct for your server)
# ------------------------------
app = Flask(__name__)
# Example paths - adjust if needed
# WAPITI_PATH = "wapiti"
# NUCLEI_PATH = "nuclei"
# NIKTO_PATH = "nikto"
# WAFW00F_PATH = "wafw00f"
# WHATWEB_PATH = "whatweb"

OUTPUT_DIR = os.path.expanduser("~/scan_results") # Or adjust as needed
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------------------
# Tool Runner
# ------------------------------
def run_tool(tool_name, command, output_file): # Added tool_name for logging
    """Runs a command using subprocess and returns the result and output file path."""
    logger.info(f"Running [{tool_name}] command: {command}")
    # It's generally safer to pass command parts as a list if possible,
    # but if the command string is pre-formatted, splitting might work.
    # Using shell=True can be a security risk if command contains untrusted input.
    # Consider refining command generation if possible. For now, using split().
    command_args = command.split()
    try:
        # Using subprocess.run for simplicity here
        result = subprocess.run(command_args, capture_output=True, text=True, check=False) # check=False to handle errors manually
        logger.info(f"[{tool_name}] STDOUT:\n{result.stdout}")
        if result.stderr:
             logger.warning(f"[{tool_name}] STDERR:\n{result.stderr}")
        return tool_name, result, output_file
    except FileNotFoundError:
        logger.error(f"[{tool_name}] Error: Command not found (check path?): {command_args[0]}")
        # Create a dummy result object to signify failure
        return tool_name, subprocess.CompletedProcess(command_args, returncode=-1, stderr=f"Command not found: {command_args[0]}"), output_file
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error running command: {command}")
        return tool_name, subprocess.CompletedProcess(command.split(), returncode=-2, stderr=f"Exception: {str(e)}"), output_file


# ------------------------------
# Cleanup Output Directory
# ------------------------------
def cleanup_scan_results():
    """Removes files and directories within the OUTPUT_DIR."""
    logger.info(f"Cleaning up output directory: {OUTPUT_DIR}")
    try:
        for filename in os.listdir(OUTPUT_DIR):
            file_path = os.path.join(OUTPUT_DIR, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                    logger.debug(f"Deleted file: {file_path}")
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                    logger.debug(f"Deleted directory: {file_path}")
            except Exception as e:
                logger.warning(f"Failed to delete {file_path}. Reason: {e}")
    except Exception as e:
        logger.error(f"Error during cleanup listing: {e}")

# ------------------------------
# Scan Endpoint (Modified)
# ------------------------------
@app.route('/scan', methods=['POST'])
def scan():
    """Receives commands, runs them concurrently, and returns results as ZIP."""
    try:
        data = request.get_json()
        logger.info(f"Received scan request with payload: {json.dumps(data, indent=2)}")

        if not data:
            logger.error("Scan request received with no JSON payload.")
            return jsonify({"error": "No JSON payload provided"}), 400

        commands = data.get("commands")
        if not commands or not isinstance(commands, dict):
            logger.error(f"Scan request received with missing or invalid 'commands' field: {commands}")
            return jsonify({"error": "Missing or invalid 'commands' dictionary"}), 400

        # --- Clean up previous results before starting new scan ---
        cleanup_scan_results()

        # Define expected tools and their output files
        tool_output_map = {
            "wapiti": os.path.join(OUTPUT_DIR, "wapiti_scan.json"),
            "nuclei": os.path.join(OUTPUT_DIR, "nuclei_scan.json"),
            "nikto": os.path.join(OUTPUT_DIR, "nikto_scan.xml"), # or .json/.txt depending on command
            "wafw00f": os.path.join(OUTPUT_DIR, "wafw00f_scan.json"), # Wafw00f might just output to stdout/stderr
            "whatweb": os.path.join(OUTPUT_DIR, "whatweb_scan.json")
        }

        results = {}
        futures_map = {} # Use this to map future back to tool_name reliably

        with ThreadPoolExecutor(max_workers=5) as executor: # Adjust max_workers if needed
            # --- Conditionally submit tasks ---
            for tool_name, output_file in tool_output_map.items():
                if tool_name in commands:
                    command_string = commands[tool_name]
                    if command_string: # Ensure the command is not empty
                        logger.info(f"Submitting task for tool: {tool_name}")
                        # Pass tool_name to run_tool for better logging/results mapping
                        future = executor.submit(run_tool, tool_name, command_string, output_file)
                        futures_map[future] = tool_name
                    else:
                         logger.warning(f"Command for tool '{tool_name}' is present but empty, skipping.")
                         results[tool_name] = {"status": "skipped", "reason": "Empty command provided"}
                else:
                    logger.info(f"No command provided for tool '{tool_name}', skipping.")
                    # Optionally record that it was skipped
                    results[tool_name] = {"status": "skipped", "reason": "Command not provided"}


            if not futures_map:
                 logger.warning("No valid tool commands were submitted for execution.")
                 # Decide how to respond - maybe an error or just the skipped results?
                 # Returning potentially empty zip for now, adjust if needed.
                 pass # Allow zip creation below

            # --- Process completed tasks ---
            for future in as_completed(futures_map):
                completed_tool_name = futures_map[future]
                try:
                    # run_tool now returns (tool_name, result_object, output_file)
                    _, result_obj, output_file_path = future.result()

                    if result_obj.returncode != 0:
                        results[completed_tool_name] = {
                            "error": f"{completed_tool_name} scan failed with return code {result_obj.returncode}",
                            "details": result_obj.stderr.strip() # Use strip() to clean up
                        }
                        logger.error(f"{completed_tool_name} failed (code {result_obj.returncode}): {result_obj.stderr.strip()}")
                    else:
                        # Check if the *expected* output file exists, even if command succeeded
                        # Note: Some tools might primarily use stdout, adapt if necessary
                        if os.path.exists(output_file_path):
                             results[completed_tool_name] = {
                                "status": f"{completed_tool_name} scan completed successfully",
                                "output_file": os.path.basename(output_file_path)
                            }
                             logger.info(f"{completed_tool_name} completed successfully. Output: {os.path.basename(output_file_path)}")
                        else:
                             # Command ran okay, but expected file is missing. Could be normal for some tools (e.g., wafw00f stdout?).
                             results[completed_tool_name] = {
                                "status": f"{completed_tool_name} scan command ran (code 0), but expected output file missing.",
                                "output_stdout": result_obj.stdout.strip() # Include stdout just in case
                             }
                             logger.warning(f"{completed_tool_name} ran successfully but did not produce expected file: {output_file_path}. Stdout captured.")

                except Exception as e:
                    # Catch exceptions from future.result() itself or within the try block
                    results[completed_tool_name] = {
                        "error": f"{completed_tool_name} scan encountered an exception during processing",
                        "details": str(e)
                    }
                    logger.exception(f"{completed_tool_name} encountered an exception")

        # --- Package results into a ZIP ---
        zip_buffer = io.BytesIO()
        files_added_to_zip = False
        logger.info("Attempting to package results into zip...") # Log start of zipping
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add actual output files generated during the scan
            for tool_name, output_file_path in tool_output_map.items():
                tool_result = results.get(tool_name, {})
                file_exists = os.path.exists(output_file_path)
                has_error = 'error' in tool_result

                # --- DETAILED LOGGING ---
                logger.debug(f"Zipping check for '{tool_name}':")
                logger.debug(f"  - Expected Path: {output_file_path}")
                logger.debug(f"  - File Exists? {file_exists}")
                logger.debug(f"  - Result Dict: {tool_result}")
                logger.debug(f"  - Has Error Key? {has_error}")
                # --- END DETAILED LOGGING ---

                # Check if the file exists AND the tool didn't report an error in the results dict
                if file_exists:
                    try:
                        logger.info(f"Adding '{os.path.basename(output_file_path)}' to zip...") # Log before adding
                        zip_file.write(output_file_path, os.path.basename(output_file_path))
                        logger.info(f"Successfully added '{os.path.basename(output_file_path)}' to zip.")
                        files_added_to_zip = True
                    except Exception as e:
                        logger.error(f"Error adding {output_file_path} to zip: {e}")
                elif not file_exists and not has_error and tool_result.get("status") != "skipped":
                     # Only log warning if the tool was supposed to run and succeed but file missing
                     logger.warning(f"Skipping zip for '{tool_name}': Tool seems to have succeeded but output file is missing.")
                # No need to log explicitly if file doesn't exist AND tool had error or was skipped

            # Optionally, add a summary JSON file with success/error statuses
            try:
                 summary_bytes = json.dumps(results, indent=2).encode('utf-8')
                 zip_file.writestr("scan_summary.json", summary_bytes)
                 logger.info("Added scan_summary.json to zip.")
                 files_added_to_zip = True # Count summary as a file
            except Exception as e:
                 logger.error(f"Error adding summary JSON to zip: {e}")


        # --- Clean up generated files AFTER zipping ---
        # Moved cleanup here to ensure files exist for zipping
        # cleanup_scan_results() # Re-enable if you want cleanup *after* zipping

        if not files_added_to_zip:
             logger.warning("Scan finished, but no output files were generated or added to the zip archive.")
             # Return something indicating no results? Or an empty zip?
             # Returning empty zip for now.

        zip_buffer.seek(0)
        logger.info("Scan process complete. Returning zip file.")
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name="scan_results.zip"
        )

    except Exception as e:
        logger.exception("Unhandled exception in /scan route")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


# ------------------------------
# Health Check Endpoint
# ------------------------------
@app.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint."""
    return jsonify({"status": "API is running"}), 200

# ------------------------------
# Run Flask App
# ------------------------------
if __name__ == '__main__':
    logger.info("Starting Flask server on http://0.0.0.0:5000")
    # Use debug=False for production/stable environments
    # Use threaded=True if needed, but be mindful of context issues if not handled properly
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
