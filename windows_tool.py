from flask import Flask, request, jsonify, send_file
import json
import os
import io
import logging
import sys
import tempfile
import shutil
import zipfile
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from windows_scanners import execute_burp_scan, execute_zap_scan

# --- Try to import scanner functions (adjust path for Windows VM) ---
SCANNER_FUNCTIONS_LOADED = False
try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    SCANNER_DIR = os.path.join(SCRIPT_DIR, "scanner")
    if SCANNER_DIR not in sys.path:
        sys.path.append(SCANNER_DIR)
    if SCRIPT_DIR not in sys.path:
        sys.path.append(SCRIPT_DIR)

    SCANNER_FUNCTIONS_LOADED = True
except Exception as e:
    # If imports fail, provide clear errors at runtime but keep the API available
    logging.getLogger(__name__).warning(
        "Scanner modules not loaded; API will run but scans will return errors. Details: %s", e
    )
    
# --- Basic logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# --- Constants ---
SCAN_SUMMARY_FILENAME = "scan_summary.json"
API_ZIP_FILENAME = "api_scan_results.zip"

# --- Flask app ---
app = Flask(__name__)

# --- Helpers ---
def ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        logger.error("Failed to create directory %s\n%s", path, traceback.format_exc())
        raise

def int_or_default(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

# --- Scan wrappers ---
def run_zap_scan_wrapper(zap_config, output_dir):
    tool = "zap"
    report_filename = "zap_scan.json"
    report_path = os.path.join(output_dir, report_filename)
    zap_config["report_path"] = report_path
    try:
        target = zap_config.get("target_url")
        logger.info("[%s] Starting scan for %s", tool.upper(), target)
        if not target:
            return tool, {"status": "skipped", "reason": "target_url missing"}

        ensure_dir(os.path.dirname(report_path))
        result = execute_zap_scan(zap_config) or {}
        status = result.get("status", "unknown")
        summary = {"status": status, "output_file": None, "reason": result.get("error")}
        if status == "completed":
            if os.path.exists(report_path):
                summary["status"] = "completed successfully"
                summary["output_file"] = report_filename
            else:
                summary["status"] = "completed_with_errors"
                summary["reason"] = "report file missing"
        return tool, summary
    except Exception as e:
        logger.error("[%s] Wrapper error: %s\n%s", tool.upper(), e, traceback.format_exc())
        return tool, {"status": "error", "reason": f"internal wrapper error: {e}"}

def run_burp_scan_wrapper(burp_config, output_dir):
    tool = "burp"
    report_filename = "burp_scan.json"
    report_path = os.path.join(output_dir, report_filename)
    burp_config["report_path"] = report_path
    try:
        target = burp_config.get("target_url")
        logger.info("[%s] Starting scan for %s", tool.upper(), target)
        if not target:
            return tool, {"status": "skipped", "reason": "target_url missing"}

        if not isinstance(burp_config.get("scan_config"), dict):
            return tool, {"status": "failed", "reason": "invalid scan_config structure"}

        ensure_dir(os.path.dirname(report_path))
        result = execute_burp_scan(burp_config) or {}
        status = result.get("status", "unknown")
        summary = {"status": status, "output_file": None, "reason": result.get("error")}
        if status == "completed":
            if os.path.exists(report_path):
                summary["status"] = "completed successfully"
                summary["output_file"] = report_filename
            else:
                summary["status"] = "completed_with_errors"
                summary["reason"] = "report file missing"
        return tool, summary
    except Exception as e:
        logger.error("[%s] Wrapper error: %s\n%s", tool.upper(), e, traceback.format_exc())
        return tool, {"status": "error", "reason": f"internal wrapper error: {e}"}

# --- API endpoint ---
@app.route("/scan", methods=["POST"])
def handle_scan_request():
    request_id = str(time.time())
    logger.info("New scan request %s", request_id)

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    try:
        options = request.get_json()
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not SCANNER_FUNCTIONS_LOADED:
        logger.error("[%s] Scanner functions not loaded", request_id)
        # Still accept requests so clients get structured errors rather than 500
        # But you may prefer to return 500 instead depending on your use-case
        return jsonify({"error": "Scanner modules not loaded on server"}), 500

    target_url = options.get("target_url")
    selected = options.get("selected_tools", {})
    use_zap = selected.get("use_zap", False)
    use_burp = selected.get("use_burp", False)

    if not target_url:
        return jsonify({"error": "Missing 'target_url'"}), 400
    if not (use_zap or use_burp):
        return jsonify({"error": "No supported tools selected (use_zap/use_burp)"}), 400

    try:
        tmpdir = tempfile.mkdtemp(prefix=f"scan_{request_id}_")
    except Exception as e:
        logger.error("[%s] Temp dir creation failed: %s", request_id, e)
        return jsonify({"error": "Failed to create temporary directory"}), 500

    scan_summary = {}
    futures = []

    # Prepare configs
    zap_config = {}
    burp_config = {}
    if use_zap:
        zap_config = {
            "target_url": target_url,
            "scan_policy": options.get("zap_scan_policy", "Default Policy"),
            "delay_in_ms": int_or_default(options.get("zap_delay"), 100),
            "threads_per_host": int_or_default(options.get("zap_threads"), 5),
            "credentials": options.get("zap_credentials"),
        }

    if use_burp:
        burp_config = {
            "target_url": target_url,
            "scan_config": {
                "name": options.get("burp_scan_config", "Crawl and Audit - Balanced"),
                "type": "NamedConfiguration",
            },
            "credentials": options.get("burp_credentials"),
        }

    start = time.time()
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            if use_zap:
                futures.append(executor.submit(run_zap_scan_wrapper, zap_config, tmpdir))
            if use_burp:
                futures.append(executor.submit(run_burp_scan_wrapper, burp_config, tmpdir))

            for fut in futures:
                try:
                    tool_name, summary = fut.result()
                    scan_summary[tool_name] = summary
                except Exception as e:
                    logger.error("[%s] Thread future error: %s", request_id, e)
                    scan_summary.setdefault("api_thread_error", []).append(
                        {"status": "error", "reason": str(e)}
                    )
    finally:
        elapsed = time.time() - start
        logger.info("[%s] Scans finished in %.2fs", request_id, elapsed)

    # Write summary file
    summary_path = os.path.join(tmpdir, SCAN_SUMMARY_FILENAME)
    try:
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(scan_summary, fh, indent=2)
    except Exception as e:
        logger.error("[%s] Failed to write summary: %s", request_id, e)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return jsonify({"error": "Failed to create summary file"}), 500

    # Build zip in memory
    zip_buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(summary_path, arcname=SCAN_SUMMARY_FILENAME)
            for tool, data in scan_summary.items():
                if isinstance(data, dict) and data.get("status") == "completed successfully" and data.get("output_file"):
                    rpt = os.path.join(tmpdir, data["output_file"])
                    if os.path.exists(rpt):
                        zf.write(rpt, arcname=data["output_file"])
        zip_buffer.seek(0)
    except Exception as e:
        logger.error("[%s] Failed to create zip: %s", request_id, e)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return jsonify({"error": "Failed to create zip archive"}), 500

    # Send file (attempt modern argument name, fallback for older Flask versions)
    try:
        return send_file(zip_buffer, mimetype="application/zip", as_attachment=True, download_name=API_ZIP_FILENAME)

    finally:
        # always cleanup
        shutil.rmtree(tmpdir, ignore_errors=True)

# --- Run (development) ---
if __name__ == "__main__":
    logger.info("Starting Flask server on 0.0.0.0:5001")
    app.run(debug=True, host="0.0.0.0", port=5001)
