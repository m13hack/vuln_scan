import os
import subprocess
import datetime
import sys

def run_command(command, timeout=60):
    """Run a command and capture its output or return the error with a timeout."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return f"Error: {result.stderr.strip()}"
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"Command '{command}' timed out after {timeout} seconds."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def collect_network_info():
    """Collects detailed network information and returns a dictionary with the results."""
    info = {}

    print("[+] Collecting ARP table...")
    info['ARP Table'] = run_command('arp -a', timeout=30)

    print("[+] Collecting DNS cache entries...")
    info['DNS Cache'] = run_command('ipconfig /displaydns', timeout=30)

    print("[+] Collecting TCP/UDP connections...")
    info['TCP/UDP Connections'] = run_command('netstat -ano', timeout=30)

    print("[+] Collecting network shares...")
    info['Network Shares'] = run_command('net share', timeout=30)

    print("[+] Collecting routing table...")
    info['Routing Table'] = run_command('route print', timeout=30)

    print("[+] Collecting wireless network information...")
    info['Wireless Networks'] = run_command('netsh wlan show networks mode=Bssid', timeout=30)

    print("[+] Collecting network adapter configuration...")
    info['Network Adapters'] = run_command('ipconfig /all', timeout=30)

    print("[+] Collecting LLDP/CDP connections...")
    info['LLDP/CDP Connections'] = run_command('powershell Get-NetLldpAgentSetting', timeout=30)

    print("[+] Collecting open ports...")
    info['Open Ports'] = run_command('netstat -an | findstr "LISTENING"', timeout=30)

    print("[+] Collecting firewall rules...")
    info['Firewall Rules'] = run_command('netsh advfirewall firewall show rule name=all', timeout=60)

    print("[+] Collecting active connections and processes...")
    info['Active Connections'] = run_command('netstat -b -o', timeout=60)

    return info

def generate_html_report(network_info):
    """Generates an HTML report from the collected network information."""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Vulnerability Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                padding: 0;
                background-color: #f4f4f4;
            }}
            h1 {{
                text-align: center;
                color: #333;
            }}
            h2 {{
                color: #0056b3;
            }}
            pre {{
                background-color: #eee;
                padding: 10px;
                border: 1px solid #ccc;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
        </style>
    </head>
    <body>
        <h1>Network Vulnerability Report</h1>
        <h2>Network Information</h2>
    """

    for key, value in network_info.items():
        if isinstance(value, list):
            value = "\n".join(value)
        elif value is None:
            value = "No data available"
        html_content += f"<h3>{key}:</h3><pre>{value}</pre>"

    html_content += """
    </body>
    </html>
    """

    html_file = f"network_vulnerability_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    try:
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"[+] HTML report generated at {html_file}")
    except Exception as e:
        print(f"Error generating HTML report: {e}")

if __name__ == "__main__":
    print("[+] Collecting network information...")
    try:
        network_info = collect_network_info()
    except Exception as e:
        print(f"Error collecting network information: {e}")
        sys.exit(1)

    print("[+] Generating report...")
    try:
        generate_html_report(network_info)
    except Exception as e:
        print(f"Error generating report: {e}")
        sys.exit(1)

    print("[+] Report generation complete!")
