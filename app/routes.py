# app/routes.py (Modified V5 - SSE for Scan Completion)
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, Response, session
import subprocess
import json
import os
import sys
import logging
import time # Import time for sleep in SSE

main_bp = Blueprint("main", __name__)

# --- Helper ---
def get_report_path():
    """Gets the absolute path to the final report file."""
    final_report_relative_path = os.path.join("core", "combine", "final_alerts.json")
    return os.path.join(current_app.root_path, "..", final_report_relative_path)

# --- Routes ---
@main_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # !!! IMPORTANT: Ensure Flask app has a SECRET_KEY set for flash() to work !!!
        try:
            # --- Collect form data (Same as previous version V3) ---
            options = {
                "target_url": request.form.get("target_url"), # Required
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
                options["custom_headers"] = request.form.get("custom_headers")
            if request.form.get("user_agent_chk") == "on" and request.form.get("user_agent"):
                options["user_agent"] = request.form.get("user_agent")
            if request.form.get("wapiti_post_data_chk") == "on" and request.form.get("wapiti_post_data"):
                options["wapiti_post_data"] = request.form.get("wapiti_post_data")
            # Tool Specific Options (ZAP, Burp, Nuclei, Wapiti - same as V3)
            if options["selected_tools"]["use_zap"]:
                options["zap_scan_policy"] = request.form.get("zap_scan_policy")
                options["zap_delay"] = request.form.get("zap_delay", 100)
                if request.form.get("zap_use_auth") == "on": options["zap_credentials"] = [{"login_url": request.form.get("zap_login_url") or options["target_url"], "username": request.form.get("zap_username"), "password": request.form.get("zap_password"), "type": "FormBasedAuthentication"}]
                else: options["zap_credentials"] = None
            if options["selected_tools"]["use_burp"]:
                options["burp_scan_config"] = request.form.get("burp_scan_config")
                if request.form.get("burp_use_auth") == "on": options["burp_credentials"] = [{"username": request.form.get("burp_username"), "password": request.form.get("burp_password"), "type": "UsernameAndPasswordLogin"}]
                else: options["burp_credentials"] = None
            if options["selected_tools"]["use_nuclei"]:
                options["nuclei_template_method"] = request.form.get("nuclei_template_method", "default")
                if options["nuclei_template_method"] == "specific": options["nuclei_templates"] = request.form.get("nuclei_templates"); options["nuclei_exclude_templates"] = None
                elif options["nuclei_template_method"] == "exclude": options["nuclei_exclude_templates"] = request.form.get("nuclei_exclude_templates"); options["nuclei_templates"] = None
                else: options["nuclei_templates"] = None; options["nuclei_exclude_templates"] = None
                options["nuclei_severity"] = request.form.getlist("nuclei_severity")
            if options["selected_tools"]["use_wapiti"]:
                options["wapiti_force"] = request.form.get("wapiti_force")
                if request.form.get("wapiti_all_modules") == "on": options["wapiti_modules"] = ["all"]
                else: options["wapiti_modules"] = request.form.getlist("wapiti_modules")
            # --- End Collect form data ---

            # --- Validate required fields ---
            if not options["target_url"]:
                 try: flash("Target URL is required.", "error")
                 except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                 return render_template("form.html")
            if not any(options["selected_tools"].values()):
                 try: flash("Please select at least one tool to run.", "error")
                 except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                 return render_template("form.html")

            options_json_string = json.dumps(options)
            current_app.logger.info(f"Prepared options for main.py: {options_json_string}")

            main_script_path = os.path.join(current_app.root_path, "..", "main.py")
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

            # --- Start main.py script in the background ---
            try:
                process = subprocess.Popen(
                    [sys.executable, main_script_path, options_json_string],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                current_app.logger.info(f"Started background scan process with PID: {process.pid}")

                # Store that a scan is running (optional, could use file existence)
                session['scan_running'] = True # Requires SECRET_KEY

                try: flash("Scan started successfully! Results page will update when ready.", "info")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return redirect(url_for("main.results"))

            except Exception as e:
                 try: flash(f"An error occurred while trying to start the scan: {e}", "error")
                 except RuntimeError as re: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {re}")
                 current_app.logger.exception("Error starting main.py subprocess")
                 return render_template("form.html")

        except Exception as e:
             try: flash(f"Error processing form data: {e}", "error")
             except RuntimeError as re: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {re}")
             current_app.logger.exception("Error processing form data in index route")
             return render_template("form.html")

    # === GET request ===
    return render_template("form.html")

@main_bp.route("/results")
def results():
    """
    Renders the results page. Tries to load results for initial display.
    If results aren't ready, the template will connect to /scan_events.
    """
    # !!! IMPORTANT: Ensure Flask app has a SECRET_KEY set for session/flash() !!!
    current_app.logger.info("Accessing /results page.")
    report_path = get_report_path()
    results_data = None
    scan_error = None
    is_running = session.get('scan_running', False) # Check if we think a scan is running

    try:
        if os.path.exists(report_path):
            # If file exists, assume scan finished (or failed and left a file)
            is_running = False
            session.pop('scan_running', None) # Clear flag if file found
            with open(report_path, 'r', encoding='utf-8') as f:
                results_data = json.load(f)
            current_app.logger.info("Loaded existing results data on /results load.")
        # else: scan is potentially still running if flag is set

    except json.JSONDecodeError:
        current_app.logger.error(f"Found results file {report_path} but it's invalid JSON.")
        scan_error = "Result file is present but invalid. Scan may have failed."
        is_running = False # Treat as finished/failed
        session.pop('scan_running', None)
    except Exception as e:
        current_app.logger.exception("Error loading initial results data:")
        scan_error = f"An error occurred loading results: {e}"
        is_running = False # Treat as finished/failed
        session.pop('scan_running', None)

    # Pass results_data, error status, and running status to the template
    return render_template("output.html",
                           results=results_data,
                           scan_error=scan_error,
                           scan_initially_running=is_running and not results_data and not scan_error)


@main_bp.route('/scan_events')
def scan_events():
    """
    Server-Sent Events endpoint. Monitors the results file and notifies the client.
    """
    current_app.logger.info("SSE connection established.")
    report_path = get_report_path()

    def generate():
        try:
            while True:
                if os.path.exists(report_path):
                    current_app.logger.info(f"SSE: Report file found at {report_path}. Checking validity.")
                    try:
                        # Check if file is valid JSON
                        with open(report_path, 'r', encoding='utf-8') as f:
                            json.load(f)
                        # File exists and is valid JSON - signal completion
                        current_app.logger.info("SSE: Report file valid. Sending scan_complete event.")
                        yield "event: scan_complete\ndata: done\n\n"
                        session.pop('scan_running', None) # Clear running flag
                        break # Stop sending events for this connection
                    except json.JSONDecodeError:
                        current_app.logger.warning("SSE: Report file exists but is invalid JSON. Sending error event.")
                        yield f"event: scan_error\ndata: Result file is invalid\n\n"
                        session.pop('scan_running', None) # Clear running flag
                        break # Stop sending events
                    except Exception as e:
                         current_app.logger.error(f"SSE: Error reading report file: {e}")
                         yield f"event: scan_error\ndata: Error checking result file\n\n"
                         session.pop('scan_running', None) # Clear running flag
                         break # Stop sending events
                else:
                    # File not found, send a comment to keep connection alive (optional)
                    # yield ": keepalive\n\n"
                    current_app.logger.debug("SSE: Report file not found. Waiting...")
                    pass # Keep waiting

                # Wait before checking again
                time.sleep(5) # Check every 5 seconds
        except GeneratorExit:
             current_app.logger.info("SSE connection closed by client.")
        except Exception as e:
             current_app.logger.error(f"SSE: Error during event generation: {e}")
        finally:
             current_app.logger.info("SSE event stream finished.")

    # Return the generator function wrapped in a Response object
    return Response(generate(), mimetype='text/event-stream')

# Remove the old /scan_status endpoint if it exists
# @main_bp.route("/scan_status") ...

