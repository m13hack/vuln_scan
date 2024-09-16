import os
import subprocess
import wmi
import datetime
import sys
import traceback
import time

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

def collect_system_info():
    """Collects system information and returns a dictionary with the results."""
    info = {}

    print("[+] Collecting basic OS information...")
    info['OS'] = run_command('systeminfo', timeout=30)

    print("[+] Collecting .NET versions...")
    info['.NET Versions'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP" /s /v Version', timeout=30)

    print("[+] Collecting AMSI Providers...")
    info['AMSI Providers'] = run_command('reg query "HKLM\\Software\\Microsoft\\AMSI\\Providers"', timeout=30)

    print("[+] Collecting antivirus information...")
    try:
        c = wmi.WMI()
        info['Antivirus'] = [a.name for a in c.Win32_Product()]
    except Exception as e:
        info['Antivirus'] = f"Error collecting antivirus info: {e}"

    print("[+] Collecting audit policy settings...")
    info['Audit Policy Settings'] = run_command('auditpol /get /category:*', timeout=30)

    print("[+] Collecting auto-run executables...")
    info['Auto-run Executables'] = run_command('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"', timeout=30)

    print("[+] Collecting firewall rules...")
    info['Firewall Rules'] = run_command('netsh advfirewall firewall show rule name=all', timeout=60)

    print("[+] Collecting Windows Defender settings...")
    info['Windows Defender Settings'] = run_command('powershell Get-MpPreference', timeout=30)

    print("[+] Collecting installed certificates...")
    info['Certificates'] = run_command('certutil -store my', timeout=30)

    print("[+] Collecting environment variables...")
    info['Environment Variables'] = run_command('set', timeout=30)

    print("[+] Collecting file information...")
    info['Files Information'] = run_command('dir /s', timeout=60)

    print("[+] Collecting installed hotfixes...")
    info['Installed Hotfixes'] = run_command('wmic qfe list', timeout=30)

    print("[+] Collecting installed products...")
    info['Installed Products'] = run_command('wmic product get name', timeout=60)

    print("[+] Collecting local group policy settings...")
    info['Local Group Policy Settings'] = run_command('gpresult /r', timeout=30)

    print("[+] Collecting local groups and users...")
    info['Local Groups'] = run_command('net localgroup', timeout=30)
    info['Local Users'] = run_command('net user', timeout=30)

    print("[+] Collecting Microsoft updates...")
    info['Microsoft Updates'] = run_command('wmic qfe list', timeout=30)

    print("[+] Collecting NTLM authentication settings...")
    info['NTLM Authentication Settings'] = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LMCompatibilityLevel', timeout=30)

    print("[+] Collecting RDP connections...")
    info['RDP Connections'] = run_command('reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"', timeout=30)

    print("[+] Collecting secure boot configuration...")
    info['Secure Boot Configuration'] = run_command('powershell Get-SecureBootPolicy', timeout=30)

    print("[+] Collecting Sysmon configuration...")
    info['Sysmon Configuration'] = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"', timeout=30)

    print("[+] Collecting UAC policies...")
    info['UAC Policies'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA', timeout=30)

    print("[+] Collecting PowerShell history...")
    info['PowerShell History'] = run_command('powershell Get-Content (Get-PSReadlineOption).HistorySavePath', timeout=30)

    return info

def collect_network_info():
    """Collects network information and returns a dictionary with the results."""
    info = {}

    print("[+] Collecting ARP table...")
    info['ARP Table'] = run_command('arp -a', timeout=30)

    print("[+] Collecting DNS cache entries...")
    info['DNS Cache'] = run_command('ipconfig /displaydns', timeout=30)

    print("[+] Collecting TCP/UDP connections...")
    info['TCP/UDP Connections'] = run_command('netstat -ano', timeout=30)

    print("[+] Collecting network shares...")
    info['Network Shares'] = run_command('net share', timeout=30)

    print("[+] Collecting LLDP/CDP connections...")
    info['LLDP/CDP Connections'] = run_command('powershell Get-NetLldpAgentSetting', timeout=30)

    print("[+] Collecting open ports...")
    info['Open Ports'] = run_command('netstat -an | findstr "LISTENING"', timeout=30)

    return info

def generate_html_report(system_info, network_info):
    """Generates an HTML report from the collected information."""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>System & Network Vulnerability Report</title>
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
        <h1>Windows System & Network Vulnerability Report</h1>
        <h2>System Information</h2>
    """

    for key, value in system_info.items():
        if isinstance(value, list):
            value = "\n".join(value)
        elif value is None:
            value = "No data available"
        html_content += f"<h3>{key}:</h3><pre>{value}</pre>"

    html_content += "<h2>Network Information</h2>"

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

    html_file = f"vulnerability_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    try:
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"[+] HTML report generated at {html_file}")
    except Exception as e:
        print(f"Error generating HTML report: {e}")

if __name__ == "__main__":
    print("[+] Collecting system information...")
    try:
        system_info = collect_system_info()
    except Exception as e:
        print(f"Error collecting system information: {e}")
        sys.exit(1)

    print("[+] Collecting network information...")
    try:
        network_info = collect_network_info()
    except Exception as e:
        print(f"Error collecting network information: {e}")
        sys.exit(1)

    print("[+] Generating report...")
    try:
        generate_html_report(system_info, network_info)
    except Exception as e:
        print(f"Error generating report: {e}")
        sys.exit(1)

    print("[+] Report generation complete!")
