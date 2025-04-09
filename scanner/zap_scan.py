import time
import json
import urllib
from zapv2 import ZAPv2

def get_zap_scan_input():
    """Get user input for ZAP scan configuration"""
    print("\n=== ZAP Scan Configuration ===")
    
    # Initialize ZAP
    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}, 
               apikey='fsem2celt7bged0jt6q8anhges')

    # Get target URL
    while True:
        target = input("Enter the target URL to scan: ").strip()
        if target.startswith(("http://", "https://")):
            break
        print("[Error] Invalid URL. Must start with http:// or https://")

    # Get available scan policies
    try:
        available_policies = zap.ascan.scan_policy_names
        print("\nAvailable Scan Policies:")
        for i, policy in enumerate(available_policies, 1):
            print(f"{i}. {policy}")
    except Exception as e:
        print(f"Error getting policies: {e}")
        available_policies = ["Default Policy"]

    # Get scan policy
    while True:
        policy_choice = input("\nEnter the number or name of scan policy: ").strip()
        if policy_choice.isdigit():
            choice_idx = int(policy_choice) - 1
            if 0 <= choice_idx < len(available_policies):
                scan_policy = available_policies[choice_idx]
                break
        elif policy_choice in available_policies:
            scan_policy = policy_choice
            break
        print("Invalid selection. Please try again.")

    # Get credentials if needed
    credentials = []
    if input("\nAdd login credentials? (y/n): ").lower() == 'y':
        if input("Seperate login url or use the target url? (y/n): ").lower() == 'y':
            login_url = input("Login URL: ").strip()
            if not login_url.startswith(("http://", "https://")):
                print("[Error] Invalid URL. Must start with http:// or https://")
                return
        else:
            login_url = target
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        if username and password and login_url:
            credentials.append({
                "username": username,
                "password": password,
                "type": "FormBasedAuthentication",
                "login_url": login_url
            })
            
    # Get scan parameters
    while True:
        try:
            delay = int(input("\nDelay between requests (ms, default 100): ") or "100")
            if delay >= 0:
                break
            print("Delay must be >= 0")
        except ValueError:
            print("Invalid number")

    while True:
        try:
            threads = int(input("Threads per host (default 5): ") or "5")
            if threads > 0:
                break
            print("Threads must be > 0")
        except ValueError:
            print("Invalid number")

    # Get report path
    report_path = "scan_results/zap/zap_scan.json"

    return {
        "target": target,
        "scan_policy": scan_policy,
        "delay": delay,
        "credentials": credentials,
        "threads": threads,
        "report_path": report_path
    }

def execute_zap_scan(scan_config):
    """Execute ZAP scan with given configuration"""
    print("\n=== Starting ZAP Scan ===")
    
    try:
        # Initialize ZAP
        zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}, 
                   apikey='fsem2celt7bged0jt6q8anhges')

        context_id = 1
        context_name = "Default Context"

        # Configure scan
        zap.ascan.set_option_delay_in_ms(scan_config.get("delay", 0))
        zap.ascan.set_option_thread_per_host(scan_config.get("threads", 1))

        credentials = scan_config.get("credentials", [])

        if credentials and all(k in credentials[0] for k in ("login_url", "username", "password")):
            login_url = credentials[0]["login_url"]
            username = credentials[0]["username"]
            password = credentials[0]["password"]

            include_url = login_url
            zap.context.include_in_context(context_name, include_url)
            print("Configured include and exclude regex(s) in context")

            # Correct way to create form data
            login_request_data = f"username='{username}'&password='{password}'"
            # Correcting form_based_config
            form_based_config = (
                f"loginUrl={urllib.parse.quote(login_url)}&"
                f"loginRequestData={urllib.parse.quote(login_request_data)}"
            )

            zap.authentication.set_authentication_method(
                context_id, "formBasedAuthentication", form_based_config
            )
            print("Configured form-based authentication")
        else:
            print("Credentials not provided or incomplete. Skipping authentication configuration.")

        print(f"Accessing target {scan_config['target']}...")
        zap.urlopen(scan_config["target"])
        time.sleep(2)

        # Run spider
        print("Running spider...")
        zap.spider.scan(scan_config["target"])
        while int(zap.spider.status()) < 100:
            print(f"\rSpider progress: {zap.spider.status()}%")
            time.sleep(5)

        # Run active scan
        print("\nRunning active scan...")
        scan_id = zap.ascan.scan(scan_config["target"], scanpolicyname=scan_config["scan_policy"])
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"\rScan progress: {zap.ascan.status(scan_id)}%",end="")
            time.sleep(2)

        # Get results
        alerts = zap.core.alerts()
        report = {
            "target": scan_config["target"],
            "scan_policy": scan_config["scan_policy"],
            "alerts": alerts,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Save report
        with open(scan_config["report_path"], "w") as f:
            json.dump(report, f, indent=4)

        return {
            "status": "completed",
            "alerts_count": len(alerts),
            "report_path": scan_config["report_path"]
        }

    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }
        
if __name__ == "__main__":
    zap_config = get_zap_scan_input()
    result = execute_zap_scan(zap_config)
    print("\n=== ZAP Scan Result ===")
    if result['status'] == 'completed':
        print(f"✅ Success! Found {result['alerts_count']} alerts")
        print(f"Report saved to: {result['report_path']}")
    else:
        print(f"❌ Failed: {result.get('error', 'Unknown error')}")
