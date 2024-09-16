import os
import subprocess
import wmi
from fpdf import FPDF
import datetime
import sys
import traceback

def run_command(command, description, capture_output=True):
    """Run a command, print progress, and capture its output or return the error."""
    print(f"[+] {description}...")
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        print(f"[+] {description} complete.")
        return result
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing {description}: {e}")
        return f"Error: {e}"
    except Exception as e:
        print(f"[-] Unexpected error in {description}: {e}")
        return f"Error: {e}"

def collect_system_info():
    """Collects system information and returns a dictionary with the results."""
    info = {}
    
    # Basic OS info
    info['OS'] = run_command('systeminfo', "Collecting basic OS information")

    # .NET versions
    info['.NET Versions'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP" /s /v Version', ".NET versions")
    
    # Antivirus info
    try:
        print("[+] Collecting antivirus information...")
        c = wmi.WMI()
        info['Antivirus'] = ', '.join([a.name for a in c.Win32_Product()])
        print("[+] Antivirus information collected.")
    except Exception as e:
        print(f"[-] Error collecting antivirus information: {e}")
        info['Antivirus'] = str(e)
    
    # Audit policy settings
    info['Audit Policy Settings'] = run_command('auditpol /get /category:*', "Collecting audit policy settings")
    
    # Auto-run executables
    info['Auto-run Executables'] = run_command('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"', "Collecting auto-run executables")
    
    # Firewall rules
    info['Firewall Rules'] = run_command('netsh advfirewall firewall show rule name=all', "Collecting firewall rules")
    
    # Windows Defender settings
    info['Windows Defender Settings'] = run_command('powershell Get-MpPreference', "Collecting Windows Defender settings")
    
    # Certificates
    info['Certificates'] = run_command('certutil -store my', "Collecting certificates")
    
    # Environment Variables
    info['Environment Variables'] = run_command('set', "Collecting environment variables")
    
    # Installed Hotfixes
    info['Installed Hotfixes'] = run_command('wmic qfe list', "Collecting installed hotfixes")
    
    # Installed Products
    info['Installed Products'] = run_command('wmic product get name', "Collecting installed products")
    
    # Local Group Policy settings
    info['Local Group Policy Settings'] = run_command('gpresult /r', "Collecting local group policy settings")
    
    # Local Groups/Users
    info['Local Groups'] = run_command('net localgroup', "Collecting local groups")
    info['Local Users'] = run_command('net user', "Collecting local users")
    
    # Microsoft Updates
    info['Microsoft Updates'] = run_command('wmic qfe list', "Collecting Microsoft updates")
    
    # NTLM Authentication Settings
    info['NTLM Authentication Settings'] = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LMCompatibilityLevel', "Collecting NTLM authentication settings")
    
    # RDP Connections
    info['RDP Connections'] = run_command('reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"', "Collecting RDP connections")
    
    # Secure Boot Configuration
    info['Secure Boot Configuration'] = run_command('powershell Get-SecureBootPolicy', "Collecting secure boot configuration")
    
    # Sysmon Configuration
    info['Sysmon Configuration'] = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"', "Collecting Sysmon configuration")
    
    # UAC Policies
    info['UAC Policies'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA', "Collecting UAC policies")
    
    # PowerShell History
    info['PowerShell History'] = run_command('powershell Get-Content (Get-PSReadlineOption).HistorySavePath', "Collecting PowerShell history")
    
    return info

def collect_network_info():
    """Collects network information and returns a dictionary with the results."""
    info = {}
    
    # ARP Table
    info['ARP Table'] = run_command('arp -a', "Collecting ARP table")
    
    # TCP/UDP connections
    info['TCP/UDP Connections'] = run_command('netstat -ano', "Collecting TCP/UDP connections")
    
    # Network Shares
    info['Network Shares'] = run_command('net share', "Collecting network shares")
    
    return info

def generate_report(system_info, network_info):
    """Generates a PDF report from the collected information."""
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', size=16)
    pdf.cell(200, 10, txt="Windows System & Network Vulnerability Report", ln=True, align="C")
    pdf.ln(10)
    
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="System Information", ln=True, align="L")
    pdf.ln(5)
    
    for key, value in system_info.items():
        pdf.set_font("Arial", 'B', size=10)
        pdf.cell(0, 10, txt=f"{key}:", ln=True, align="L")
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, value.strip() if value else "N/A")
        pdf.ln()
    
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="Network Information", ln=True, align="L")
    pdf.ln(5)
    
    for key, value in network_info.items():
        pdf.set_font("Arial", 'B', size=10)
        pdf.cell(0, 10, txt=f"{key}:", ln=True, align="L")
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, value.strip() if value else "N/A")
        pdf.ln()
    
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
