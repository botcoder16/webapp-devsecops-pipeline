import requests
from bs4 import BeautifulSoup
import json

# URL of the ZAP Alert Details page
url = "https://www.zaproxy.org/docs/alerts/"

# Fetch the page content
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# Locate the main table
table = soup.find('table', attrs={'data-sort-filter': True})
rows = table.find('tbody').find_all('tr')

alerts = {}

# Parse each row
for row in rows:
    cols = row.find_all('td')
    if len(cols) < 7:
        continue  # skip malformed rows

    alert_id = cols[0].get_text(strip=True)
    name = cols[1].get_text(strip=True)
    status = cols[2].get_text(strip=True)
    risk = cols[3].get_text(strip=True)
    alert_type = cols[4].get_text(strip=True)
    cwe = cols[5].get_text(strip=True)
    wasc = cols[6].get_text(strip=True)

    alerts[alert_id] = {
        "name": name,
        "status": status,
        "risk": risk,
        "type": alert_type,
        "cwe": cwe,
        "wasc": wasc
    }

# Save to a JSON file
with open("zap_alert_catalog.json", "w") as f:
    json.dump(alerts, f, indent=4)

print(f"Scraped and saved {len(alerts)} ZAP alert definitions to zap_alert_catalog.json")
