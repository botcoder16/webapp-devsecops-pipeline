import json

# Load the JSON report
with open("meterian_report.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Extract project details
project_name = data.get("name", "Unknown Project")
timestamp = data.get("timestamp", "N/A")
security_score = data.get("scores", {}).get("security", "N/A")
stability_score = data.get("scores", {}).get("stability", "N/A")

print(f"\n🔹 Project Name: {project_name}")
print(f"📅 Scan Timestamp: {timestamp}")
print(f"🔐 Security Score: {security_score}")
print(f"📈 Stability Score: {stability_score}")

# Extract security reports
security_reports = data.get("reports", {}).get("security", {}).get("reports", [])

print("\n📌 **Vulnerable Dependencies:**")
if not security_reports:
    print("✅ No security vulnerabilities found.")
else:
    for language_report in security_reports:
        language = language_report.get("language", "Unknown Language")
        print(f"\n🛠️ **Language:** {language}")

        for idx, report in enumerate(language_report.get("reports", []), 1):
            dependency = report.get("dependency", {})
            name = dependency.get("name", "Unknown")
            version = dependency.get("version", "Unknown")
            hierarchy = report.get("hierarchy", [])
            dependency_chain = " ➝ ".join(hierarchy) if hierarchy else "N/A"

            print(f"\n🔻 **{idx}. {name} ({version})**")
            print(f"   🔗 Dependency Chain: {dependency_chain}")

            for advice in report.get("advices", []):  
                severity = advice.get("severity", "Unknown")
                description = advice.get("description", "No description provided.")
                cve = advice.get("cve", "No CVE")
                cvss = advice.get("cvss", "Unknown")

                print(f"     🔸 Severity: {severity}")
                print(f"     🔍 CVE: {cve} (CVSS: {cvss})")
                print(f"     📝 {description}")

                links = advice.get("links", [])
                if links:
                    print("     🔗 References:")
                    for link in links:
                        print(f"       - {link.get('type', 'INFO')}: {link.get('url', 'No URL')}")

            print("\n" + "-" * 80 + "\n")
# Extract stability reports
print("\n✅ Scan Completed!")