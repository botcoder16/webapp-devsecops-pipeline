import json

def simplify_security_scan(json_data):
    simplified_results = {}
    
    for alert in json_data.get('alerts', []):
        alert_key = (
            alert.get("alert", "Unknown Alert"),
            alert.get("risk", "Unknown Risk"),
            alert.get("confidence", "Unknown Confidence"),
            alert.get("description", "No description provided."),
            alert.get("solution", "No solution provided."),
            alert.get("reference", "No reference provided.")
        )
        
        tags = alert.get("tags", {})
        url = alert.get("url", "No URL provided.")
        param = alert.get("param", "No parameter provided.")
        evidence = alert.get("evidence", "No evidence provided.")

        if alert_key not in simplified_results:
            simplified_results[alert_key] = {
                "alert": alert_key[0],
                "risk": alert_key[1],
                "confidence": alert_key[2],
                "description": alert_key[3],
                "solution": alert_key[4],
                "reference": alert_key[5],
                "tags": list(tags.values()),
                "urls": []  # List to store URLs for this alert
            }
        
        simplified_results[alert_key]["urls"].append({
            "url": url,
            "param": param,
            "evidence": evidence
        })
    
    return list(simplified_results.values())


# Example usage:
if __name__ == "__main__":
    with open("../scan_results/zap/zap_scan.json", "r") as file:
        data = json.load(file)
    
    simplified_json = simplify_security_scan(data)
    
    with open("../combine/vulnerabilities_zap.json", "w") as outfile:
        json.dump(simplified_json, outfile, indent=4)
    
    print("Simplified JSON saved as vulnerabilities_zap.json")
