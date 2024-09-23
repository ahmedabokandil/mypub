import paramiko
import requests
import time

# Configuration
FEED_URLS = [
    'https://lists.blocklist.de/lists/all.txt',
    'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'http://www.ciarmy.com/list/ci-badguys.txt',
    'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
]
MIKROTIK_IP = ''  # Replace with your MikroTik IP address
MIKROTIK_USER = ''  # Replace with your MikroTik username
MIKROTIK_PASS = ''  # Replace with your MikroTik password
UPDATE_INTERVAL = 3600  # Update interval in seconds (e.g., 3600 seconds = 1 hour)

# Function to download threat intelligence feed
def download_feed(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text.splitlines()

# Function to download from all feeds and combine results
def download_all_feeds(urls):
    all_ips = set()
    for url in urls:
        try:
            ips = download_feed(url)
            all_ips.update(ips)
        except Exception as e:
            print(f'Error downloading feed from {url}: {e}')
    return all_ips

# Function to connect to MikroTik router via SSH
def mikrotik_connect(ip, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=password)
    return client

# Function to update MikroTik firewall rules
def update_firewall(client, ips):
    # Clear existing rules
    client.exec_command('/ip firewall address-list remove [/ip firewall address-list find list=threat_list]')
    # Add new rules
    for ip in ips:
        client.exec_command(f'/ip firewall address-list add list=threat_list address={ip}')

def main():
    while True:
        try:
            # Download and parse the feeds
            ips = download_all_feeds(FEED_URLS)
            # Connect to MikroTik router
            client = mikrotik_connect(MIKROTIK_IP, MIKROTIK_USER, MIKROTIK_PASS)
            # Update firewall rules
            update_firewall(client, ips)
            # Close the connection
            client.close()
            print('Firewall updated successfully.')
        except Exception as e:
            print(f'Error: {e}')
        # Wait for the next update
        time.sleep(UPDATE_INTERVAL)

if __name__ == '__main__':
    main()
