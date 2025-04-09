from flask import Flask, request, jsonify
import subprocess
import os
import json
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# Tool paths (adjust if needed)
WAPITI_PATH = "/home/tool/.local/bin/wapiti"
NUCLEI_PATH = "nuclei"  # Ensure Nuclei is in your PATH
NIKTO_PATH = "nikto"    # Ensure Nikto is in your PATH
WAFW00F_PATH = "wafw00f"  # Ensure WAFW00F is in your PATH
WHATWEB_PATH = "whatweb"  # Ensure WhatWeb is in your PATH
OUTPUT_DIR = os.path.expanduser("~/scan_results")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_wapiti(commands, output_file):
    """Run Wapiti and return the results."""
    command = [commands["wapiti"], "-o", output_file]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result, output_file

def run_nuclei(commands, output_file):
    """Run Nuclei and return the results."""
    command = [commands["nuclei"], "-o", output_file]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result, output_file

def run_nikto(commands, output_file):
    """Run Nikto and return the results."""
    command = [commands["nikto"], "-output", output_file]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result, output_file

def run_wafw00f(commands, output_file):
    """Run WAFW00F and return the results."""
    command = [commands["wafw00f"], "-o", output_file]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result, output_file

def run_whatweb(commands, output_file):
    """Run WhatWeb and return the results."""
    command = [commands["whatweb"], "--log", output_file]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result, output_file

@app.route('/scan', methods=['POST'])
def scan():
    try:
        # Parse JSON payload
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON payload provided"}), 400

        # Extract target URL
        commands = data.get("commands")
        if not commands:
            return jsonify({"error": "Missing commands"}), 400

        # Generate unique output file names
        wapiti_output_file = os.path.join(OUTPUT_DIR, f"wapiti_scan_{uuid4().hex}.json")
        nuclei_output_file = os.path.join(OUTPUT_DIR, f"nuclei_scan_{uuid4().hex}.json")
        nikto_output_file = os.path.join(OUTPUT_DIR, f"nikto_scan_{uuid4().hex}.json")
        wafw00f_output_file = os.path.join(OUTPUT_DIR, f"wafw00f_scan_{uuid4().hex}.json")
        whatweb_output_file = os.path.join(OUTPUT_DIR, f"whatweb_scan_{uuid4().hex}.json")

        # Run tools in parallel using ThreadPoolExecutor
        results = {}
        with ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(run_wapiti, commands, wapiti_output_file): "wapiti",
                executor.submit(run_nuclei, commands, nuclei_output_file): "nuclei",
                executor.submit(run_nikto, commands, nikto_output_file): "nikto",
                executor.submit(run_wafw00f, commands, wafw00f_output_file): "wafw00f",
                executor.submit(run_whatweb, commands, whatweb_output_file): "whatweb"
            }

            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    result, output_file = future.result()
                    if result.returncode != 0:
                        results[tool_name] = {
                            "error": f"{tool_name} scan failed",
                            "details": result.stderr
                        }
                    else:
                        with open(output_file, "r") as f:
                            results[tool_name] = json.load(f)
                except Exception as e:
                    results[tool_name] = {
                        "error": f"{tool_name} scan encountered an exception",
                        "details": str(e)
                    }

        return jsonify({
            "message": "Scan completed",
            "results": results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "API is running"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)