import requests
from bs4 import BeautifulSoup
import json

# Target URL
url = "https://portswigger.net/burp/documentation/scanner/vulnerabilities-list"

# Fetch page content
headers = {
    "User-Agent": "Mozilla/5.0"
}
response = requests.get(url, headers=headers)
soup = BeautifulSoup(response.text, "html.parser")

# Find the table
table = soup.find("table", class_="kb-issues-table")
rows = table.find("tbody").find_all("tr")

vulnerabilities = {}

# Parse each row
for row in rows:
    cols = row.find_all("td")
    if len(cols) < 5:
        continue

    name_tag = cols[0].find("a")
    name = name_tag.text.strip()
    link = f"https://portswigger.net{name_tag['href']}"

    severity = cols[1].text.strip()
    hex_index = cols[2].text.strip()
    dec_index = cols[3].text.strip()
    cwe_tags = cols[4].find_all("a")
    cwe_list = [cwe.text.strip() for cwe in cwe_tags]

    vulnerabilities[dec_index] = {
        "name": name,
        "link": link,
        "severity": severity,
        "index_hex": hex_index,
        "index_dec": dec_index,
        "cwe": cwe_list
    }

# Write to JSON
with open("burp_vulnerabilities.json", "w") as f:
    json.dump(vulnerabilities, f, indent=4)

print(f"Scraped and saved {len(vulnerabilities)} Burp vulnerability definitions to burp_vulnerabilities.json")
