import requests
import socket
import subprocess
import json
import time
import logging
import psutil
import platform

# Setup logging for better debugging and error tracking
logging.basicConfig(filename="scan_logs.txt", level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Define the API URLs for getting IP information
IPINFO_API_URL = 'https://ipinfo.io/{}/json'
WHOIS_API_URL = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YourAPIKeyHere&domainName={}&outputFormat=JSON'

# Function to fetch IP information (including VPN, ISP, and IPv6)
def get_ip_info(ip):
    try:
        ip_info_response = requests.get(IPINFO_API_URL.format(ip))
        ip_info = ip_info_response.json()

        if "error" in ip_info:
            raise ValueError(f"Error fetching IP info: {ip_info['error']}")

        vpn_detected = "VPN" in ip_info.get("org", "").lower()

        whois_response = requests.get(WHOIS_API_URL.format(ip))
        whois_info = whois_response.json()

        return ip_info, vpn_detected, whois_info
    except Exception as e:
        logging.error(f"Error while fetching IP info: {e}")
        return None, None, None

# Function to run a subprocess command (ping or traceroute)
def run_subprocess(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        logging.error(f"Subprocess error: {e}")
        return f"Error: {e}"

# Function to perform traceroute to the given IP address
def traceroute(ip):
    command = ['traceroute', ip]
    return run_subprocess(command)

# Function to scan ports in a range on the given IP address
def scan_ports(ip, port_range=(1, 10)):
    open_ports = []
    for port in range(port_range[0], port_range[1] + 1):
        if check_port(ip, port):
            open_ports.append(port)
    return open_ports

# Function to check if a port is open
def check_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        logging.error(f"Port checking error: {e}")
        return False

# Function to perform a ping sweep on the IP address
def ping_sweep(ip):
    command = ['ping', '-c', '1', ip]
    return run_subprocess(command)

# Function to get IPv6 if available
def get_ipv6(ip_info):
    return ip_info.get("ipv6", "Not available")

# Function to gather system information
def get_system_info():
    try:
        # CPU info
        cpu_count = psutil.cpu_count(logical=True)
        cpu_model = platform.processor() or "Unknown"
        cpu_arch = platform.architecture()[0]
        
        # Memory info
        memory = psutil.virtual_memory()
        total_memory = memory.total / (1024 ** 3)  # Convert to GB
        available_memory = memory.available / (1024 ** 3)  # Convert to GB
        
        # Machine and Architecture
        machine = platform.machine()
        architecture = platform.architecture()[0]
        system = platform.system()

        # Processor info
        processor = platform.processor()

        # System Information Dictionary
        system_info = {
            "CPU Count": cpu_count,
            "CPU Model": cpu_model,
            "CPU Architecture": cpu_arch,
            "Total Memory (GB)": total_memory,
            "Available Memory (GB)": available_memory,
            "Machine": machine,
            "Architecture": architecture,
            "System": system,
            "Processor": processor
        }

        return system_info
    except Exception as e:
        logging.error(f"Error while fetching system info: {e}")
        return None

# Main function to execute all tasks
def main():
    ip = input("Enter the IP address to analyze: ")
    start_time = time.time()

    # Fetch IP information (ISP, VPN, etc.)
    ip_info, vpn_detected, whois_info = get_ip_info(ip)
    if not ip_info:
        logging.error(f"Failed to fetch IP information for {ip}.")
        print(f"Error: Failed to fetch IP information for {ip}.")
        return

    # Fetch system information
    system_info = get_system_info()
    if not system_info:
        logging.error(f"Failed to fetch system information.")
        print(f"Error: Failed to fetch system information.")
        return

    # Perform tasks (sequentially for simplicity and stability)
    trace_result = traceroute(ip)
    open_ports = scan_ports(ip)
    ping_result = ping_sweep(ip)
    ipv6 = get_ipv6(ip_info)
    isp = ip_info.get("org", "ISP not found")

    # Compile results
    results = {
        "IP Address": ip,
        "VPN Status": vpn_detected,
        "Traceroute": trace_result,
        "Open Ports (1-10)": open_ports,
        "Ping Sweep Result": ping_result,
        "IPv6": ipv6,
        "ISP": isp,
        "WHOIS Info": whois_info,
        "System Info": system_info
    }

    # Write results to a text file
    with open(f"scan_results_{ip}.txt", 'w') as f:
        for key, value in results.items():
            f.write(f"{key}: {value}\n")

    # Save results as JSON for future analysis
    with open(f"scan_results_{ip}.json", 'w') as f:
        json.dump(results, f, indent=4)

    elapsed_time = time.time() - start_time
    logging.info(f"Scan completed in {elapsed_time:.2f} seconds for IP: {ip}")
    print(f"Scan complete! Results saved in scan_results_{ip}.txt and scan_results_{ip}.json")

# Run the script
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Error during the scan execution: {e}")
        print(f"Error: {e}")
