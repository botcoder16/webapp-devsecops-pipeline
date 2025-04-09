from input import collect_scan_options
from commands.generate_nuclei_command import generate_nuclei_command
from commands.generate_wapiti_command import generate_wapiti_command
from commands.nikto import generate_nikto_command
from commands.wafw00f import generate_wafw00f_command
from commands.whatweb import generate_whatweb_command
from scanner.zap_scan import get_zap_scan_input, execute_zap_scan
from scanner.burp_pro_scan import get_burp_scan_input, execute_burp_scan
import requests
import os
import zipfile
import io
import threading
from concurrent.futures import ThreadPoolExecutor

API_URL = "http://192.168.111.134:5000/scan"
OUTPUT_DIR = "scan_results"
ZIP_FILE = "scan_results.zip"

def collect_all_inputs():
    """Collect all scan inputs sequentially before execution"""
    print("=== Collecting All Scan Inputs ===")
    
    # 1. First collect options for API scan commands
    print("\n[1/3] Configuring API scan commands...")
    options = collect_scan_options()
    
    # 2. Then get ZAP scan configuration
    print("\n[2/3] Configuring ZAP scan...")
    zap_config = get_zap_scan_input()
    
    # 3. Finally get Burp scan configuration
    print("\n[3/3] Configuring Burp scan...")
    burp_config = get_burp_scan_input()
    
    return {
        'options': options,
        'zap_config': zap_config,
        'burp_config': burp_config
    }

def run_api_scan(options):
    """Execute API scan with pre-collected options"""
    try:
        print("\n[API] Starting API tools scan...")
        payload = {
            "commands": {
                "nuclei": generate_nuclei_command(options),
                "wapiti": generate_wapiti_command(options),
                "nikto": generate_nikto_command(options),
                "wafw00f": generate_wafw00f_command(options),
                "whatweb": generate_whatweb_command(options)
            }
        }
        
        # Print generated commands for verification
        print("[API] Generated commands:")
        print(f"- Nuclei: {generate_nuclei_command(options)}")
        print(f"- Wapiti: {generate_wapiti_command(options)}")
        print(f"- Nikto: {generate_nikto_command(options)}")
        print(f"- Wafw00f: {generate_wafw00f_command(options)}")
        print(f"- WhatWeb: {generate_whatweb_command(options)}")
        
        response = requests.post(API_URL, json=payload, headers={"Content-Type": "application/json"})
        
        if response.status_code == 200:
            with open(ZIP_FILE, "wb") as f:
                f.write(response.content)
            
            with zipfile.ZipFile(ZIP_FILE, 'r') as zip_ref:
                zip_ref.extractall(OUTPUT_DIR)
            
            # Organize output files
            for tool_name in ["wapiti", "nuclei", "nikto", "wafw00f", "whatweb"]:
                tool_output_dir = os.path.join(OUTPUT_DIR, tool_name)
                os.makedirs(tool_output_dir, exist_ok=True)
                for file in os.listdir(OUTPUT_DIR):
                    if file.startswith(f"{tool_name}_scan") and file.endswith((".json",".xml")):
                        os.rename(
                            os.path.join(OUTPUT_DIR, file),
                            os.path.join(tool_output_dir, file)
                        )
            
            return {
                'status': 'completed',
                'output_dir': OUTPUT_DIR,
                'zip_file': ZIP_FILE
            }
        else:
            return {
                'status': 'failed',
                'error': f"API error: {response.status_code}",
                'response': response.text
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def run_zap_scan(zap_config):
    """Execute ZAP scan with pre-collected configuration"""
    try:
        print("\n[ZAP] Starting ZAP scan...")
        return execute_zap_scan(zap_config)
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def run_burp_scan(burp_config):
    """Execute Burp scan with pre-collected configuration"""
    try:
        print("\n[BURP] Starting Burp scan...")
        return execute_burp_scan(burp_config)
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def main():
    # First collect all inputs sequentially
    inputs = collect_all_inputs()
    
    # Then execute all scans simultaneously using multithreading
    print("\n=== Starting All Scans Simultaneously ===")
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all scan tasks
        api_future = executor.submit(run_api_scan, inputs['options'])
        zap_future = executor.submit(run_zap_scan, inputs['zap_config'])
        burp_future = executor.submit(run_burp_scan, inputs['burp_config'])
        
        # Wait for all tasks to complete
        api_result = api_future.result()
        zap_result = zap_future.result()
        burp_result = burp_future.result()
    
    # Print consolidated results
    print("\n=== All Scans Completed ===")
    
    # API Results
    print("\n[API Scan Results]")
    if api_result['status'] == 'completed':
        print(f"✅ Success! Results saved to: {api_result['output_dir']}")
    else:
        print(f"❌ Failed: {api_result.get('error', 'Unknown error')}")
    
    # ZAP Results
    print("\n[ZAP Scan Results]")
    if zap_result['status'] == 'completed':
        print(f"✅ Success! Found {zap_result.get('alerts_count', 0)} alerts")
        print(f"Report saved to: {zap_result.get('report_path', 'unknown')}")
    else:
        print(f"❌ Failed: {zap_result.get('error', 'Unknown error')}")
    
    # Burp Results
    print("\n[Burp Scan Results]")
    if burp_result['status'] == 'completed':
        print(f"✅ Success! Found {burp_result.get('issues_count', 0)} issues")
        print(f"Report saved to: {burp_result.get('report_path', 'unknown')}")
    else:
        print(f"❌ Failed: {burp_result.get('error', 'Unknown error')}")

if __name__ == "__main__":
    main()