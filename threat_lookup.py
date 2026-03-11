import requests

API_KEY = "3259ccd3075ba4eda559ddcd04591ca9c111a1d9b95914015d4b9bfa961d0c90dcb680546a7e6ca1"

def lookup_ip(ip):
    """Query AbuseIPDB and return IP threat information."""
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json().get("data", {})

    # Handle cases where AbuseIPDB returns incomplete data
    result = {
        "IP": data.get("ipAddress", "N/A"),
        "Country": data.get("countryCode", "N/A"),
        "ISP": data.get("isp", "N/A"),
        "Abuse Score": data.get("abuseConfidenceScore", 0),
        "Reports": data.get("totalReports", 0)
    }

    return result
