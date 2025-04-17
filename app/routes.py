# app/routes.py (Modified V7.2 - User's Index Logic Integrated)
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, Response, session, g
import subprocess
import json
import os
import sys
import logging
import threading
import time
import queue # For thread communication

main_bp = Blueprint("main", __name__)

# --- Globals / State Management (Simple for single-scan-at-a-time) ---
# WARNING: This simple global state is NOT suitable for concurrent scans.
# Use Flask-Executor, Celery, or more robust state management for that.
scan_process_info = {
    "process": None,
    "final_status_json": None, # Store the last JSON line from main.py stdout
    "lock": threading.Lock() # To protect access
}
output_log_queue = queue.Queue() # Queue for logs from main.py

# --- Helper ---
def get_report_path():
    """Gets the absolute path to the final report file."""
    # Ensure this path calculation is correct relative to your project structure
    project_root = os.path.abspath(os.path.join(current_app.root_path, ".."))
    final_report_relative_path = os.path.join("core", "combine", "final_alerts.json")
    return os.path.join(project_root, final_report_relative_path)

# --- Thread Functions ---
# (process_monitor and log_stream_output functions remain the same as in V7.1)
def process_monitor(app_instance):
    """
    Monitors the scan process, captures final status, and waits for completion.
    This runs in a separate thread started by the index route.
    """
    global scan_process_info
    process = None
    pid = -1

    with scan_process_info["lock"]:
        if scan_process_info["process"]:
            process = scan_process_info["process"]
            pid = process.pid

    if not process:
        app_instance.logger.error("[Monitor] No process found to monitor.")
        return

    app_instance.logger.info(f"[Monitor] Monitoring process PID: {pid}")

    last_line = ""
    stdout_lines = [] # Store all output if needed for debugging

    # Read output line by line
    try:
        # Use a separate thread to avoid blocking this one on readline
        log_thread = threading.Thread(target=log_stream_output, args=(process.stdout, app_instance, output_log_queue), daemon=True)
        log_thread.start()

        # Wait for the process to finish
        return_code = process.wait() # This blocks until the process exits
        log_thread.join(timeout=5) # Wait briefly for the log thread to finish processing remaining output

        app_instance.logger.info(f"[Monitor] Process PID {pid} finished with exit code: {return_code}")

        # Try to get the last status JSON from the queue
        final_status = None
        try:
            # Look backwards in the queue for the last potential JSON status
            # Create a temporary list to avoid modifying queue while iterating (though get_nowait is used)
            log_items = list(output_log_queue.queue)
            for item in reversed(log_items):
                 if item and item.strip().startswith('{') and item.strip().endswith('}'):
                      try:
                           parsed = json.loads(item.strip())
                           if 'status' in parsed: # Check if it looks like our status JSON
                                final_status = item.strip()
                                app_instance.logger.info(f"[Monitor] Found final status JSON in queue: {final_status}")
                                break
                      except json.JSONDecodeError:
                           continue # Ignore lines that aren't valid JSON
            if not final_status:
                 app_instance.logger.warning(f"[Monitor] Could not find final status JSON in queue for PID {pid}.")

        except Exception as e:
            app_instance.logger.error(f"[Monitor] Error retrieving final status from queue: {e}")


        # If no JSON status found via queue, check exit code
        if not final_status and return_code != 0:
            final_status = json.dumps({"status": "runtime_error", "error": f"Process exited with code {return_code}"})
            app_instance.logger.warning(f"[Monitor] Process {pid} exited non-zero ({return_code}) without clear status JSON.")
        elif not final_status and return_code == 0:
             # Check if report file exists if exit code is 0 but no status found
             report_path = get_report_path()
             if os.path.exists(report_path):
                   final_status = json.dumps({"status": "success", "report_path": report_path}) # Assume success
                   app_instance.logger.warning(f"[Monitor] Process {pid} exited zero, no status JSON, but report file found. Assuming success.")
             else:
                  final_status = json.dumps({"status": "runtime_error", "error": "Process exited zero but produced no status or report file."})
                  app_instance.logger.warning(f"[Monitor] Process {pid} exited zero, no status JSON, no report file found.")


        # Store final status
        with scan_process_info["lock"]:
            scan_process_info["final_status_json"] = final_status
            scan_process_info["process"] = None # Mark process as finished

        app_instance.logger.info(f"[Monitor] Finished monitoring PID {pid}. Final status stored.")

    except Exception as e:
        app_instance.logger.exception(f"[Monitor] Error during process monitoring for PID {pid}:")
        with scan_process_info["lock"]:
            scan_process_info["final_status_json"] = json.dumps({"status": "runtime_error", "error": f"Monitoring thread failed: {e}"})
            scan_process_info["process"] = None # Ensure process is marked finished on error


def log_stream_output(pipe, app, log_queue):
    """Reads subprocess output, logs it, and puts it on a queue."""
    for line in iter(pipe.readline, ''):
        if line:
            stripped_line = line.strip()
            app.logger.info(f"[main.py] {stripped_line}")
            try:
                log_queue.put(stripped_line, block=False) # Add to queue (non-blocking)
            except queue.Full:
                 app.logger.warning("[LogStream] Log queue is full, discarding message.") # Should not happen with default queue size
    pipe.close()
    app.logger.info("[LogStream] Subprocess stream finished.")

# --- Routes ---

# *****************************************************************************
# *********************** START: USER PROVIDED INDEX ROUTE (INTEGRATED) *******
# *****************************************************************************
@main_bp.route("/", methods=["GET", "POST"])
def index():
    global scan_process_info # Use the global state

    if request.method == "POST":
        # --- Prevent starting new scan if one is running ---
        with scan_process_info["lock"]:
            if scan_process_info["process"] is not None and scan_process_info["process"].poll() is None:
                current_app.logger.warning("Scan attempt rejected: Another scan is already running.")
                try: flash("Another scan is already in progress. Please wait.", "warning")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return redirect(url_for("main.results")) # Redirect to results page

            # Reset state for a new scan
            scan_process_info["process"] = None
            scan_process_info["final_status_json"] = None
            while not output_log_queue.empty(): # Clear old logs from queue
                try: output_log_queue.get_nowait()
                except queue.Empty: break

        # !!! IMPORTANT: Ensure Flask app has a SECRET_KEY set for flash() to work !!!
        try:
            # --- Collect form data (User Provided Logic) ---
            options = {
                "target_url": request.form.get("target_url", "").strip(), # Required, strip whitespace
                "selected_tools": {
                    "use_zap": request.form.get("use_zap") == "on",
                    "use_burp": request.form.get("use_burp") == "on",
                    "use_nuclei": request.form.get("use_nuclei") == "on",
                    "use_wapiti": request.form.get("use_wapiti") == "on",
                    "use_nikto": request.form.get("use_nikto") == "on",
                    "use_whatweb": request.form.get("use_whatweb") == "on",
                    "use_wafw00f": request.form.get("use_wafw00f") == "on",
                },
                "output_format": "json", # Hardcoded for now
                "verbose": request.form.get("verbose") == "on",
                "max_depth": request.form.get("max_depth"),
                "max_links": request.form.get("max_links"),
                "disable_ssl_verify": request.form.get("disable_ssl_verify") == "on",
            }
            # Conditionally add optional general settings
            if request.form.get("thread_concurrency_chk") == "on" and request.form.get("thread_concurrency"):
                options["thread_concurrency"] = request.form.get("thread_concurrency")
            if request.form.get("rate_limit_chk") == "on" and request.form.get("rate_limit"):
                options["rate_limit"] = request.form.get("rate_limit")
            if request.form.get("timeout_chk") == "on" and request.form.get("timeout"):
                options["timeout"] = request.form.get("timeout")
            if request.form.get("max_scan_time_chk") == "on" and request.form.get("max_attack_time"):
                options["max_attack_time"] = request.form.get("max_attack_time")
            if request.form.get("custom_headers_chk") == "on" and request.form.get("custom_headers"):
                # Attempt to parse headers as JSON, fallback to raw string if invalid
                try:
                    headers_dict = json.loads(request.form.get("custom_headers"))
                    if isinstance(headers_dict, dict):
                         options["custom_headers"] = headers_dict
                    else:
                         options["custom_headers"] = request.form.get("custom_headers") # Keep as string if not dict
                         current_app.logger.warning("Custom headers provided but not valid JSON object, sending as string.")
                except json.JSONDecodeError:
                     options["custom_headers"] = request.form.get("custom_headers") # Keep as string on parse error
                     current_app.logger.warning("Could not parse custom headers as JSON, sending as raw string.")
            if request.form.get("user_agent_chk") == "on" and request.form.get("user_agent"):
                options["user_agent"] = request.form.get("user_agent")
            if request.form.get("wapiti_post_data_chk") == "on" and request.form.get("wapiti_post_data"):
                options["wapiti_post_data"] = request.form.get("wapiti_post_data")

            # Tool Specific Options (ZAP, Burp, Nuclei, Wapiti - User Provided Logic)
            # Wrap credential creation in checks for tool selection AND auth checkbox
            if options["selected_tools"]["use_zap"]:
                options["zap_scan_policy"] = request.form.get("zap_scan_policy")
                options["zap_delay"] = request.form.get("zap_delay") # Let main.py handle default/conversion
                options["zap_threads"] = request.form.get("zap_threads") # Let main.py handle default/conversion
                if request.form.get("zap_use_auth") == "on":
                    # Assuming main.py now expects a dict, not a list
                    zap_creds = {
                         "username": request.form.get("zap_username"),
                         "password": request.form.get("zap_password")
                         # Add other ZAP auth fields as needed by main.py here
                         # "login_url": request.form.get("zap_login_url"),
                         # "type": "FormBasedAuthentication" # If needed
                    }
                    # Only add credentials if username/password are provided
                    if zap_creds.get("username") and zap_creds.get("password"):
                         options["zap_credentials"] = zap_creds
                    else:
                         options["zap_credentials"] = None
                         current_app.logger.warning("ZAP auth checked, but username/password missing.")
                else:
                    options["zap_credentials"] = None # Explicitly set to None if auth not used

            if options["selected_tools"]["use_burp"]:
                options["burp_scan_config"] = request.form.get("burp_scan_config")
                if request.form.get("burp_use_auth") == "on":
                    # Assuming main.py now expects a dict, not a list
                    burp_creds = {
                        "username": request.form.get("burp_username"),
                        "password": request.form.get("burp_password")
                        # Add other Burp auth fields as needed by main.py here
                        # "type": "UsernameAndPasswordLogin" # If needed
                    }
                     # Only add credentials if username/password are provided
                    if burp_creds.get("username") and burp_creds.get("password"):
                         options["burp_credentials"] = burp_creds
                    else:
                         options["burp_credentials"] = None
                         current_app.logger.warning("Burp auth checked, but username/password missing.")
                else:
                    options["burp_credentials"] = None # Explicitly set to None if auth not used

            if options["selected_tools"]["use_nuclei"]:
                options["nuclei_template_method"] = request.form.get("nuclei_template_method", "default")
                if options["nuclei_template_method"] == "specific":
                    options["nuclei_templates"] = request.form.get("nuclei_templates")
                    options["nuclei_exclude_templates"] = None
                elif options["nuclei_template_method"] == "exclude":
                    options["nuclei_exclude_templates"] = request.form.get("nuclei_exclude_templates")
                    options["nuclei_templates"] = None
                else: # Default case
                    options["nuclei_templates"] = None
                    options["nuclei_exclude_templates"] = None
                # Use getlist for multi-select severity checkboxes
                options["nuclei_severity"] = request.form.getlist("nuclei_severity")

            if options["selected_tools"]["use_wapiti"]:
                options["wapiti_scope"] = request.form.get("wapiti_scope") # Added scope based on previous version
                options["wapiti_force"] = request.form.get("wapiti_force") # e.g., maybe 'sql,xss' if force needed
                if request.form.get("wapiti_all_modules") == "on":
                    # Wapiti might expect specific format like '-a' or similar in command generator
                    # Let's pass 'all' and let the command generator handle it.
                    options["wapiti_modules"] = ["all"]
                else:
                    options["wapiti_modules"] = request.form.getlist("wapiti_modules")

            # --- End Collect form data ---

            # Remove keys with None or empty string values if main.py prefers absence
            options = {k: v for k, v in options.items() if v is not None and v != ""}
            # Ensure selected_tools dict is always present, even if empty inside
            if "selected_tools" not in options: options["selected_tools"] = {}


            # --- Validate required fields ---
            if not options.get("target_url"):
                try: flash("Target URL is required.", "error")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return render_template("form.html")
            # Check the inner dict values for tool selection
            if not options.get("selected_tools") or not any(options["selected_tools"].values()):
                try: flash("Please select at least one tool to run.", "error")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return render_template("form.html")

            options_json_string = json.dumps(options)
            current_app.logger.info(f"Prepared options for main.py: {options_json_string}")

            # --- Get Paths ---
            project_root = os.path.abspath(os.path.join(current_app.root_path, ".."))
            main_script_path = os.path.join(project_root, "main.py")
            current_app.logger.info(f"Attempting to run script: {main_script_path} using {sys.executable}")

            if not os.path.exists(main_script_path):
                current_app.logger.error(f"Main script not found at {main_script_path}")
                try: flash("Error: Backend script not found.", "error")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return render_template("form.html")

            # --- Clean up old report before starting ---
            report_path = get_report_path()
            if os.path.exists(report_path):
                try:
                    os.remove(report_path)
                    current_app.logger.info(f"Removed old report file: {report_path}")
                except OSError as e:
                    current_app.logger.error(f"Error removing old report file {report_path}: {e}")
                    # Optional: flash warning?

            # --- Start main.py script in the background (Integrated with V7.1 state) ---
            try:
                env = os.environ.copy()
                process = subprocess.Popen(
                    [sys.executable, main_script_path, options_json_string],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, # Merge stderr (as in V7.1)
                    text=True,
                    bufsize=1, # Line-buffered
                    cwd=project_root, # Run from project root (as in V7.1)
                    env=env
                )
                current_app.logger.info(f"Started background scan process with PID: {process.pid}")

                # --- Store process info (V7.1 logic) ---
                with scan_process_info["lock"]:
                    scan_process_info["process"] = process
                    scan_process_info["final_status_json"] = None # Explicitly clear status

                # --- Start the monitoring thread (V7.1 logic) ---
                app_instance = current_app._get_current_object()
                monitor_thread = threading.Thread(target=process_monitor, args=(app_instance,), daemon=True)
                monitor_thread.start()
                current_app.logger.info(f"Started monitor thread for PID: {process.pid}")

                # Removed session['scan_running'] = True - Rely on global state now

                try: flash("Scan started successfully! Results page will update when ready.", "info")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return redirect(url_for("main.results"))

            except Exception as e:
                current_app.logger.exception("Error starting main.py subprocess")
                try: flash(f"An error occurred while trying to start the scan: {e}", "error")
                except RuntimeError as re: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {re}")
                # Reset process info if startup failed
                with scan_process_info["lock"]:
                    scan_process_info["process"] = None
                    scan_process_info["final_status_json"] = json.dumps({"status": "runtime_error", "error": f"Failed to start scan process: {e}"})
                return render_template("form.html")

        except Exception as e:
            current_app.logger.exception("Error processing form data in index route")
            try: flash(f"Error processing form data: {e}", "error")
            except RuntimeError as re: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {re}")
            return render_template("form.html")

    # === GET request ===
    # Check if a scan is running on GET load too
    is_running = False
    with scan_process_info["lock"]:
        if scan_process_info["process"] is not None and scan_process_info["process"].poll() is None:
            is_running = True
    if is_running:
         try: flash("A scan is currently in progress. Redirecting to results...", "info")
         except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
         return redirect(url_for("main.results"))

    return render_template("form.html")

# *****************************************************************************
# *********************** END: USER PROVIDED INDEX ROUTE (INTEGRATED) *********
# *****************************************************************************


# --- Results Route ---
# (/results route remains the same as in V7.1)
@main_bp.route("/results")
def results():
    global scan_process_info
    current_app.logger.info("Accessing /results page.")
    report_path = get_report_path()
    results_data = {}
    scan_error = None
    is_running = False
    final_status_data = None

    with scan_process_info["lock"]:
        if scan_process_info["process"] is not None and scan_process_info["process"].poll() is None:
            is_running = True
        if scan_process_info["final_status_json"] is not None:
            is_running = False
            try:
                final_status_data = json.loads(scan_process_info["final_status_json"])
            except json.JSONDecodeError:
                scan_error = "Scan finished, but final status was invalid."

    try:
        if final_status_data:
            status = final_status_data.get("status", "unknown")
            if status == "success":
                if os.path.exists(report_path):
                    try:
                        with open(report_path, 'r', encoding='utf-8') as f:
                            results_data = json.load(f)
                        if not isinstance(results_data, dict):
                            current_app.logger.error("Loaded results are not a dictionary.")
                            results_data = {}
                            scan_error = "Invalid results format."
                        else:
                            current_app.logger.info("Scan completed successfully, results loaded.")
                    except Exception as e:
                        current_app.logger.exception("Error reading results file:")
                        scan_error = f"Could not read scan result file: {e}"
                else:
                    scan_error = "Scan reported success, but result file is missing."
            else:
                scan_error = f"Scan failed: {final_status_data.get('error', 'Unknown error')}"
        elif is_running:
            pass  # scan is running
        else:
            if os.path.exists(report_path):
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        results_data = json.load(f)
                    if not isinstance(results_data, dict):
                        current_app.logger.error("Loaded results are not a dictionary.")
                        results_data = {}
                        scan_error = "Invalid results format."
                except Exception as e:
                    scan_error = f"Found previous report file, but couldn't read it: {e}"
            elif scan_process_info["final_status_json"]:
                try:
                    final_status_data = json.loads(scan_process_info["final_status_json"])
                    scan_error = f"Scan failed: {final_status_data.get('error', 'Unknown error')}"
                except:
                    scan_error = "Scan failed with unreadable status."
            else:
                scan_error = "Scan is not running and no results found."

    except Exception as e:
        current_app.logger.exception("Error checking results status:")
        scan_error = f"An error occurred: {e}"
        is_running = False

    return render_template("output.html",
                           results=json.dumps(results_data),
                           scan_error=scan_error,
                           scan_initially_running=is_running)

# --- SSE Route ---
# (/scan_events route remains the same as in V7.1)
@main_bp.route('/scan_events')
def scan_events():
    """
    Server-Sent Events endpoint. Monitors scan state based on global info.
    """
    global scan_process_info
    # ✅ Get actual app instance - safer for logging
    app = current_app._get_current_object()
    report_path = get_report_path() # Uses current_app but should be fine here

    app.logger.info("SSE connection established.") # Log connection start

    def generate():
        last_status_sent = None # Avoid sending same status repeatedly
        try:
            while True:
                current_status_json = None
                is_process_running = False

                with scan_process_info["lock"]:
                    final_status = scan_process_info["final_status_json"]
                    process = scan_process_info["process"]
                    if process is not None and process.poll() is None:
                        is_process_running = True
                    # Use final_status if available (process finished)
                    current_status_json = final_status

                event_to_send = None
                data_to_send = None

                if current_status_json: # Process has finished, use its final status
                    if current_status_json != last_status_sent:
                        try:
                            status_data = json.loads(current_status_json)
                            status = status_data.get("status", "unknown")
                            if status == "success":
                                event_to_send = "scan_complete"
                                data_to_send = "Scan completed successfully."
                                app.logger.info("SSE: Sending scan_complete based on final status.")
                            else:
                                event_to_send = "scan_error"
                                error_detail = status_data.get('error', status) # Get specific error if available
                                data_to_send = f"Scan failed: {error_detail}" # Send detailed error
                                app.logger.info(f"SSE: Sending scan_error based on final status: {status}")
                        except json.JSONDecodeError:
                            event_to_send = "scan_error"
                            data_to_send = "Scan finished with invalid final status."
                            app.logger.error(f"SSE: Invalid final status JSON: {current_status_json}")
                        except Exception as e:
                            event_to_send = "scan_error"
                            data_to_send = f"Error processing final status: {e}"
                            app.logger.error(f"SSE: Error processing final status: {e}")

                        last_status_sent = current_status_json # Update last sent status
                    # If status already sent or process finished, break the loop for this client
                    if event_to_send:
                         # Escape newline characters in data for SSE
                         data_to_send_escaped = data_to_send.replace('\n', '\\n')
                         yield f"event: {event_to_send}\ndata: {data_to_send_escaped}\n\n"
                    break # Stop sending events once final status is known

                elif is_process_running:
                    # Process is still running, send keepalive or status update if desired
                    # Send a PING event periodically if needed by client-side timeouts
                    yield "event: ping\ndata: running\n\n"
                    pass # Keep waiting

                else: # No process running, no final status yet (should be brief state before monitor updates)
                    app.logger.debug("SSE: Waiting for process to finish or monitor to update status.")
                    # Send a PING event while waiting too
                    yield "event: ping\ndata: waiting for status\n\n"
                    pass # Keep waiting


                # Wait before checking again
                time.sleep(3) # Check every 3 seconds

        except GeneratorExit:
            app.logger.info("SSE connection closed by client.")
        except Exception as e:
            app.logger.error(f"SSE: Error during event generation: {e}")
        finally:
            app.logger.info("SSE event stream finished for this connection.")

    # Return the generator function wrapped in a Response object
    return Response(generate(), mimetype='text/event-stream', headers={'Cache-Control': 'no-cache'})