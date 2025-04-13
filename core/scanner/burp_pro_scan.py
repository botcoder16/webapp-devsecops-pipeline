import time
import json
import requests
import subprocess

def get_burp_scan_input():
    """Get user input for Burp scan configuration"""
    print("\n=== Burp Scan Configuration ===")
    
    # Get target URL
    while True:
        target = input("Enter the target URL to scan: ").strip()
        if target.startswith(("http://", "https://")):
            break
        print("[Error] Invalid URL. Must start with http:// or https://")

    # Get scan configuration
    scan_configs = {
        "1": {"name": "Crawl and Audit - Balanced", "type": "NamedConfiguration"},
        "2": {"name": "Crawl and Audit - Deep", "type": "NamedConfiguration"},
        "3": {"name": "Crawl and Audit - Fast", "type": "NamedConfiguration"},
        "4": {"name": "Crawl and Audit - Lightweight", "type": "NamedConfiguration"}
    }

    print("\nSelect scan configuration:")
    for num, config in scan_configs.items():
        print(f"{num}. {config['name']}")

    while True:
        choice = input("Enter your choice (1-4): ").strip()
        if choice in scan_configs:
            scan_config = scan_configs[choice]
            break
        print("Invalid choice. Please try again.")

    # Get credentials if needed
    credentials = []
    if input("\nAdd login credentials? (y/n): ").lower() == 'y':
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        if username and password:
            credentials.append({
                "username": username,
                "password": password,
                "type": "UsernameAndPasswordLogin"
            })

    # Get report path
    report_path = "scan_results/burp/burp_scan.json"

    return {
        "target": target,
        "scan_config": scan_config,
        "credentials": credentials,
        "report_path": report_path
    }

def execute_burp_scan(scan_config):
    """Execute Burp scan with given configuration"""
    print("\n=== Starting Burp Scan ===")
    
    try:
        # Start Burp if needed
        # try:
        #     subprocess.Popen(["D:\\extra\\Burp-Suite-Pro-main\\Burp.bat"])
        #     print("Launched Burp Suite")
        #     time.sleep(10)  # Wait for Burp to initialize
        # except Exception as e:
        #     print(f"Note: {e} - Assuming Burp is already running")

        # API configuration
        headers = {
            "Authorization": "7PBgTDH8LNzsWBBRyxKAk0ov9pkRWrdz",
            "Content-Type": "application/json"
        }

        # Prepare scan payload
        payload = {
            "urls": [scan_config["target"]],
            "scan_configurations": [scan_config["scan_config"]],
            "protocol_option": "httpAndHttps"
        }

        if scan_config["credentials"]:
            payload["application_logins"] = scan_config["credentials"]

        # Start scan
        response = requests.post(
            "http://127.0.0.1:1337/v0.1/scan",
            headers=headers,
            json=payload
        )

        if response.status_code != 201:
            return {
                "status": "failed",
                "error": f"API error: {response.status_code}",
                "response": response.text
            }

        scan_id = response.headers["Location"].split("/")[-1]
        print(f"Scan started. ID: {scan_id}")

        # Monitor scan progress
        while True:
            status_response = requests.get(
                f"http://127.0.0.1:1337/v0.1/scan/{scan_id}",
                headers=headers
            )

            if status_response.status_code != 200:
                return {
                    "status": "failed",
                    "error": f"Status check failed: {status_response.status_code}"
                }

            data = status_response.json()
            status = data.get("scan_status")
            metrics = data.get("scan_metrics", {})
            
            print(f"\rStatus: {status} | Progress: {metrics.get('crawl_and_audit_progress', 0)}%", end="")
            
            if status in ["succeeded", "failed"]:
                print("\nScan finished!")
                break

            time.sleep(2)

        # Get final results
        results = {
            "target": scan_config["target"],
            "status": status,
            "metrics": metrics,
            "issues": data.get("issue_events", []),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save report
        with open(scan_config["report_path"], "w") as f:
            json.dump(results, f, indent=4)

        return {
            "status": "completed",
            "scan_status": status,
            "issues_count": len(results["issues"]),
            "report_path": scan_config["report_path"]
        }

    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }