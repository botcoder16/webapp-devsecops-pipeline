import requests

url="http://192.168.111.134:5000/scan"
response = requests.get(url)

# Save the JSON file
if response.status_code == 200:
    with open("meterian_report.json", "wb") as file:
        file.write(response.content)
    print("Report downloaded successfully!")
else:
    print("Error:", response.json())