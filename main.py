import requests
import json

# Replace YOUR_API_KEY with your actual API key
api_key = "*****************"

# Replace HASH_VALUE with the hash you want to check
hash_value = input("Please enter the hash value: ")

# Make the API call to VirusTotal
url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={hash_value}"
response = requests.get(url)

# Parse the JSON response
data = json.loads(response.text)

# Print the results
if data["response_code"] == 0:
    print("No information available for this hash.")
else:
    print("Scan date:", data["scan_date"])
    print("Detection rate:", data["positives"]/data["total"]*100, "%")
    print("Scan results:")
    for result in data["scans"]:
        print(f"{result}: {data['scans'][result]['result']}")
