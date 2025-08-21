import time
import json
import urllib.parse
from zapv2 import ZAPv2
import requests
import os
import traceback
import logging

logger = logging.getLogger(__name__)

# ----------------------------
# ZAP SCANNER
# ----------------------------
def execute_zap_scan(scan_config):
    """Execute ZAP scan with given configuration"""
    print("\n=== Starting ZAP Scan ===")
    try:
        zap = ZAPv2(
            proxies={
                'http': 'http://127.0.0.1:8081',
                'https': 'http://127.0.0.1:8081'
            },
            apikey='fsem2celt7bged0jt6q8anhges'
        )

        context_id = 1
        context_name = "Default Context"

        url = scan_config.get("target_url")
        delay = scan_config.get("delay_in_ms", 100)
        threads = scan_config.get("threads_per_host", 5)
        credentials = scan_config.get("credentials", [])
        scan_policy = scan_config.get("scan_policy", "Default Policy")

        zap.ascan.set_option_delay_in_ms(delay)
        zap.ascan.set_option_thread_per_host(threads)

        # Authentication
        if credentials and all(k in credentials[0] for k in ("login_url", "username", "password")):
            login_url = credentials[0]["login_url"]
            username = credentials[0]["username"]
            password = credentials[0]["password"]

            zap.context.include_in_context(context_name, login_url)
            print("Configured include and exclude regex(s) in context")

            login_request_data = f"username={username}&password={password}"
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

        print(f"Accessing target {url}...")
        zap.urlopen(url)
        time.sleep(2)

        print("Running spider...")
        zap.spider.scan(url)
        while int(zap.spider.status()) < 100:
            print(f"\rSpider progress: {zap.spider.status()}%", end="")
            time.sleep(5)

        print("\nRunning active scan...")
        scan_id = zap.ascan.scan(url, scanpolicyname=scan_policy)
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"\rScan progress: {zap.ascan.status(scan_id)}%", end="")
            time.sleep(2)

        alerts = zap.core.alerts()
        report = {
            "target": url,
            "scan_policy": scan_policy,
            "alerts": alerts,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        with open(scan_config["report_path"], "w") as f:
            json.dump(report, f, indent=4)

        return {
            "status": "completed",
            "alerts_count": len(alerts),
            "report_path": scan_config["report_path"]
        }
    except Exception as e:
        return {"status": "failed", "error": str(e)}


# ----------------------------
# BURP SCANNER
# ----------------------------
def execute_burp_scan(scan_config):
    """Execute Burp scan with given configuration received from API wrapper."""
    tool_name = "BURP"
    logger.info(f"[{tool_name}] === Starting Burp Scan Execution ===")
    logger.debug(f"[{tool_name}] Received scan_config: {json.dumps(scan_config)}")

    try:
        burp_api_url = "http://127.0.0.1:1337"
        burp_api_key = "3dQS5h1LoDt4NXk5DsHH8JzaFUjtWhPi"

        if burp_api_key == "YOUR_BURP_API_KEY":
            logger.error(f"[{tool_name}] Burp API Key is not set.")
            return {"status": "failed", "error": "Burp API Key not configured"}

        headers = {
            "Authorization": burp_api_key,
            "Content-Type": "application/json"
        }

        scan_endpoint = f"{burp_api_url}/v0.1/scan"
        status_endpoint_base = f"{burp_api_url}/v0.1/scan"

        target_url = scan_config.get("target_url")
        burp_scan_config_obj = scan_config.get("scan_config")
        credentials = scan_config.get("credentials")

        if not target_url:
            return {"status": "failed", "error": "Missing target_url"}
        if not burp_scan_config_obj:
            return {"status": "failed", "error": "Missing scan_config object"}

        payload = {
            "urls": [target_url],
            "scan_configurations": [burp_scan_config_obj],
            "protocol_option": "httpAndHttps"
        }

        if credentials:
            payload["application_logins"] = credentials
            logger.info(f"[{tool_name}] Adding application_logins to payload.")

        logger.info(f"[{tool_name}] Sending scan request to {scan_endpoint}")
        response = requests.post(scan_endpoint, headers=headers, json=payload, timeout=60)

        if response.status_code != 201:
            return {
                "status": "failed",
                "error": f"Failed to start Burp scan (API error: {response.status_code})",
                "response": response.text
            }

        location_header = response.headers.get("Location")
        if not location_header:
            return {"status": "failed", "error": "Scan started but Scan ID not found"}

        scan_id = location_header.split("/")[-1]
        logger.info(f"[{tool_name}] Scan ID: {scan_id}")

        status_url_template = f"{status_endpoint_base}/{scan_id}?api_key={burp_api_key}"

        while True:
            status_response = requests.get(status_url_template, headers=headers, timeout=30)
            if status_response.status_code != 200:
                return {
                    "status": "failed",
                    "error": f"Status check API call failed (Status: {status_response.status_code})"
                }

            data = status_response.json()
            status = data.get("scan_status", "unknown").lower()
            metrics = data.get("scan_metrics", {})
            progress = metrics.get('crawl_and_audit_progress', 0)

            logger.info(f"[{tool_name}] Scan Status: {status} | Progress: {progress}%")
            if status in ["succeeded", "failed"]:
                break
            time.sleep(10)

        report_path = scan_config.get("report_path", "burp_scan_report.json")
        results_dict = {
            "target": target_url,
            "final_scan_status": status,
            "metrics": metrics,
            "issue_events": data.get("issue_events", []),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(results_dict, f, indent=4)

        return {
            "status": "completed",
            "scan_status": status,
            "issues_count": len(results_dict["issue_events"]),
            "report_path": report_path
        }

    except requests.exceptions.RequestException as req_err:
        return {"status": "failed", "error": f"Network error: {req_err}"}
    except KeyError as key_err:
        return {"status": "failed", "error": f"Configuration key error: {key_err}"}
    except Exception as e:
        return {"status": "failed", "error": f"Unexpected error: {e}"}
