import requests

# ---------------------------
# AbuseIPDB Lookup
# ---------------------------
def check_abuseipdb(ip, api_key):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    return response.json()


# ---------------------------
# VirusTotal Lookup
# ---------------------------
def check_virustotal(ip, api_key):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    return response.json()


# ---------------------------
# AlienVault OTX Lookup
# ---------------------------
def check_otx(ip, api_key):

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

    headers = {
        "X-OTX-API-KEY": api_key
    }

    response = requests.get(url, headers=headers)

    return response.json()