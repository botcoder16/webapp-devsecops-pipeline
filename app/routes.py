# app/routes.py (Modified V4 - Async Scan & Status Check)
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, session
import subprocess
import json
import os
import sys # Import sys to get executable path
import logging
import time # For potential cleanup logic

main_bp = Blueprint("main", __name__)

# Configure logging for Flask app context if not already done in __init__.py
# logging.basicConfig(level=logging.INFO) # Or use Flask's logger: current_app.logger

# --- Helper ---
def get_report_path():
    """Gets the absolute path to the final report file."""
    # Assuming run.py is in the project root, and app is a subdirectory
    final_report_relative_path = os.path.join("core", "combine", "final_alerts.json")
    return os.path.join(current_app.root_path, "..", final_report_relative_path)

# --- Routes ---
@main_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # !!! IMPORTANT: Ensure Flask app has a SECRET_KEY set for flash() to work !!!
        # Example in your app/__init__.py or run.py:
        # import os
        # app.config['SECRET_KEY'] = os.urandom(24) # Or a static secret string

        try:
            # --- Collect form data (Same as previous version) ---
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

            # Convert options dict to JSON string for main.py argument
            options_json_string = json.dumps(options)
            current_app.logger.info(f"Prepared options for main.py: {options_json_string}")

            # --- Get main.py path ---
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
                    # Decide if this is critical - maybe proceed anyway?

            # --- Start main.py script in the background ---
            try:
                # Use Popen to run asynchronously
                process = subprocess.Popen(
                    [sys.executable, main_script_path, options_json_string],
                    stdout=subprocess.PIPE, # Capture stdout/stderr if needed for logging
                    stderr=subprocess.PIPE,
                    text=True,
                    # Set appropriate working directory if main.py relies on it
                    # cwd=os.path.dirname(main_script_path) # Example: Run from script's dir
                )
                current_app.logger.info(f"Started background scan process with PID: {process.pid}")
                # Don't wait for completion here (process.wait() or process.communicate())

                # --- Redirect to results page immediately ---
                try: flash("Scan started successfully! Results will appear below when ready.", "info")
                except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                return redirect(url_for("main.results"))

            except FileNotFoundError:
                 try: flash(f"Error: Python executable not found at {sys.executable}.", "error")
                 except RuntimeError as e: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {e}")
                 current_app.logger.error(f"Python executable not found: {sys.executable}")
                 return render_template("form.html")
            except Exception as e:
                 try: flash(f"An error occurred while trying to start the scan: {e}", "error")
                 except RuntimeError as re: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {re}")
                 current_app.logger.exception("Error starting main.py subprocess")
                 return render_template("form.html")

        except Exception as e:
             # Catch errors during form processing itself
             try: flash(f"Error processing form data: {e}", "error")
             except RuntimeError as re: current_app.logger.error(f"Flash failed (SECRET_KEY missing?): {re}")
             current_app.logger.exception("Error processing form data in index route")
             return render_template("form.html")

    # === GET request ===
    # Just render the form template
    return render_template("form.html")

@main_bp.route("/results")
def results():
    """
    Renders the results page. Initially, it might show a placeholder.
    JavaScript on the page will poll /scan_status to check for completion.
    """
    # !!! IMPORTANT: Ensure Flask app has a SECRET_KEY set for flash() to work !!!
    current_app.logger.info("Accessing /results page.")
    # Try to load results immediately in case the user refreshes after completion
    report_path = get_report_path()
    results_data = None
    scan_error = None
    try:
        if os.path.exists(report_path):
            with open(report_path, 'r', encoding='utf-8') as f:
                results_data = json.load(f)
            current_app.logger.info("Loaded existing results data on /results load.")
    except json.JSONDecodeError:
        current_app.logger.error(f"Found results file {report_path} but it's invalid JSON.")
        scan_error = "Result file is present but invalid. Scan may have failed."
        # Optionally delete the corrupt file
        # try: os.remove(report_path)
        # except OSError: pass
    except Exception as e:
        current_app.logger.exception("Error loading initial results data:")
        scan_error = f"An error occurred loading results: {e}"

    # Pass results_data (which might be None) and error status to the template
    return render_template("output.html", results=results_data, scan_error=scan_error)


@main_bp.route("/scan_status")
def scan_status():
    """
    API endpoint for JavaScript to poll. Checks if the results file exists.
    """
    report_path = get_report_path()
    current_app.logger.debug(f"Checking scan status, report path: {report_path}")

    if os.path.exists(report_path):
        try:
            # Optional: Check file age or basic JSON validity
            # file_mod_time = os.path.getmtime(report_path)
            # Check if file is reasonably recent?

            # Try loading JSON to ensure it's complete and valid
            with open(report_path, 'r', encoding='utf-8') as f:
                json.load(f) # Just try to load it
            current_app.logger.debug("Scan status: completed (file exists and is valid JSON).")
            # Don't return full results here, just status. Page will reload.
            return jsonify({"status": "completed"})
        except json.JSONDecodeError:
            current_app.logger.warning(f"Scan status: error (file exists but invalid JSON - {report_path}).")
            return jsonify({"status": "error", "message": "Result file is invalid."})
        except Exception as e:
            current_app.logger.error(f"Scan status: error (checking file failed: {e}).")
            return jsonify({"status": "error", "message": f"Error checking result file: {e}"})
    else:
        current_app.logger.debug("Scan status: running (file does not exist).")
        return jsonify({"status": "running"})

