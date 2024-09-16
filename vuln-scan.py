import os
import subprocess
import wmi
from fpdf import FPDF
import datetime
import sys
import traceback
import time
import concurrent.futures

def run_command(command, timeout=30):
    """Run a command and capture its output with a timeout."""
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

    commands = {
        'OS': 'systeminfo',
        '.NET Versions': 'reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP" /s /v Version',
        'Audit Policy Settings': 'auditpol /get /category:*',
        'Auto-run Executables': 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
        'Firewall Rules': 'netsh advfirewall firewall show rule name=all',
        'Windows Defender Settings': 'powershell Get-MpPreference',
        'Certificates': 'certutil -store my',
        'Environment Variables': 'set',
        'Files Information': 'dir /s',
        'Installed Hotfixes': 'wmic qfe list',
        'Installed Products': 'wmic product get name',
        'Local Group Policy Settings': 'gpresult /r',
        'Local Groups': 'net localgroup',
        'Local Users': 'net user',
        'Microsoft Updates': 'wmic qfe list',
        'NTLM Authentication Settings': 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LMCompatibilityLevel',
        'RDP Connections': 'reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"',
        'Secure Boot Configuration': 'powershell Get-SecureBootPolicy',
        'Sysmon Configuration': 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"',
        'UAC Policies': 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA',
        'PowerShell History': 'powershell Get-Content (Get-PSReadlineOption).HistorySavePath'
    }

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_command, cmd): name for name, cmd in commands.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                info[name] = future.result()
            except Exception as e:
                info[name] = f"Error collecting {name}: {e}"

    print("[+] Collecting antivirus information...")
    try:
        c = wmi.WMI()
        info['Antivirus'] = ', '.join([a.name for a in c.Win32_Product()])
    except Exception as e:
        info['Antivirus'] = f"Error collecting antivirus info: {e}"

    return info

def collect_network_info():
    """Collects network information and returns a dictionary with the results."""
    info = {}

    commands = {
        'ARP Table': 'arp -a',
        'TCP/UDP Connections': 'netstat -ano',
        'Network Shares': 'net share'
    }

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_command, cmd): name for name, cmd in commands.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                info[name] = future.result()
            except Exception as e:
                info[name] = f"Error collecting {name}: {e}"

    return info

def generate_report(system_info, network_info):
    """Generates a PDF report from the collected information."""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt="Windows System & Network Vulnerability Report", ln=True, align="C")
    pdf.ln(10)

    def add_section(title, data):
        """Helper to add sections to the PDF."""
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=title, ln=True, align="L")
        pdf.ln(5)

        for key, value in data.items():
            pdf.set_font("Arial", size=10, style='B')
            pdf.cell(0, 10, txt=f"{key}:", ln=True, align="L")
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 10, value or "No data")
            pdf.ln()

    add_section("System Information", system_info)
    add_section("Network Information", network_info)

    pdf_file = f"vulnerability_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    try:
        pdf.output(pdf_file)
        print(f"[+] PDF report generated at {pdf_file}")
    except Exception as e:
        print(f"Error generating PDF report: {e}")

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
        generate_report(system_info, network_info)
    except Exception as e:
        print(f"Error generating report: {e}")
        sys.exit(1)

    print("[+] Report generation complete!")
