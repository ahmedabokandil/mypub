import requests
import re
from urllib3.exceptions import InsecureRequestWarning

# Suppress the InsecureRequestWarning for unverified SSL requests
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Threat intel feeds
feeds = [
    'https://lists.blocklist.de/lists/all.txt',
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'http://www.ciarmy.com/list/ci-badguys.txt',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
]

# Sophos XG Firewall API URL and credentials
sophos_api_url = 'https://{{ip_FW}}:4444/webconsole/APIController'
# add admin username and password
sophos_username = ''
sophos_password = ''

BATCH_SIZE = 1000  # Define batch size for sending IPs
MAX_IPHOST_ENTRIES = 1000  # Maximum allowed entries per IPHost list

def fetch_ips(feed_url):
    """Fetches IPs from a given feed."""
    try:
        response = requests.get(feed_url)
        response.raise_for_status()  # Check for HTTP errors
        return response.text.splitlines()
    except Exception as e:
        print(f"Failed to fetch {feed_url}: {e}")
        return []

def extract_ips_from_csv(csv_text):
    """Extracts IPs from a CSV formatted list (used by some feeds)."""
    return [line.split(",")[1].strip() for line in csv_text.splitlines() if "," in line]

def validate_ip(ip):
    """Validates if the string is a valid IPv4 address."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) is not None

def create_sophos_api_request(ip_list, unique_name):
    """Generates an XML API request to add the IPs to Sophos."""
    ip_list_str = ",".join(ip_list)  # No spaces between commas
    xml_payload = f"""
    <Request>
        <Login>
            <Username>{sophos_username}</Username>
            <Password>{sophos_password}</Password>
        </Login>
        <Set operation="add">
            <IPHost transactionid="">
                <Name>{unique_name}</Name>
                <IPFamily>IPv4</IPFamily>
                <HostType>IPList</HostType>
                <ListOfIPAddresses>{ip_list_str}</ListOfIPAddresses>
            </IPHost>
        </Set>
    </Request>
    """
    return xml_payload

def send_request(xml_payload):
    """Send the API request to Sophos."""
    response = requests.post(sophos_api_url, data={'reqxml': xml_payload}, verify=False)

    if response.status_code == 200:
        print("Request sent successfully. Response:")
        print(response.text)
        return response.text
    else:
        print(f"Failed to send request. HTTP Status Code: {response.status_code}")
        return None

def check_existing_names(response_xml):
    """Checks if a name already exists in the firewall (based on response XML)."""
    if "Entity having same name already exists" in response_xml:
        return True
    return False

def generate_unique_name(base_name, existing_names, batch_index):
    """Generates a unique name to avoid overwriting existing IP hosts."""
    candidate_name = f"{base_name}_Batch_{batch_index}"
    while candidate_name in existing_names:
        batch_index += 1
        candidate_name = f"{base_name}_Batch_{batch_index}"
    return candidate_name

def batch_and_send(ip_list, base_name):
    """Split IPs into batches and send multiple requests with unique names."""
    existing_names = set()  # Track existing names to avoid overwriting

    for i in range(0, len(ip_list), BATCH_SIZE):
        batch = ip_list[i:i + BATCH_SIZE]  # Take a batch of IPs
        unique_name = generate_unique_name(base_name, existing_names, i // BATCH_SIZE)
        xml_payload = create_sophos_api_request(batch, unique_name)
        response_xml = send_request(xml_payload)

        # Check if the name already exists and handle it accordingly
        if response_xml and check_existing_names(response_xml):
            print(f"Name {unique_name} already exists. Skipping or generating a new name.")
            unique_name = generate_unique_name(base_name, existing_names, i // BATCH_SIZE + 1)
        else:
            print(f"Batch {i // BATCH_SIZE} processed successfully with name {unique_name}.")
            existing_names.add(unique_name)

def main():
    ip_set = set()

    # Fetch IPs from all feeds
    for feed in feeds:
        if 'csv' in feed:
            csv_text = requests.get(feed).text
            ips = extract_ips_from_csv(csv_text)
        else:
            ips = fetch_ips(feed)
        ip_set.update(ips)

    # Validate and filter IPs
    valid_ip_list = [ip for ip in ip_set if validate_ip(ip)]

    if not valid_ip_list:
        print("No valid IPs found.")
        return

    # Split the IPs into batches and send them to Sophos
    base_name = "Threat_Intel_Blocklist"
    batch_and_send(valid_ip_list, base_name)

if __name__ == '__main__':
    main()
