import os
import subprocess
import wmi
from fpdf import FPDF
import datetime
import sys
import traceback

def run_command(command, capture_output=True):
    """Run a command and capture its output or return the error."""
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error executing command '{command}': {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def collect_system_info():
    """Collects system information and returns a dictionary with the results."""
    info = {}
    
    # Basic OS info
    info['OS'] = run_command('systeminfo')

    # .NET versions
    info['.NET Versions'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP" /s /v Version')
    
    # Antivirus info
    try:
        c = wmi.WMI()
        info['Antivirus'] = [a.name for a in c.Win32_Product()]
    except Exception as e:
        info['Antivirus'] = str(e)
    
    # Audit policy settings
    info['Audit Policy Settings'] = run_command('auditpol /get /category:*')
    
    # Auto-run executables
    info['Auto-run Executables'] = run_command('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"')
    
    # Firewall rules
    info['Firewall Rules'] = run_command('netsh advfirewall firewall show rule name=all')
    
    # Windows Defender settings
    info['Windows Defender Settings'] = run_command('powershell Get-MpPreference')
    
    # Certificates
    info['Certificates'] = run_command('certutil -store my')
    
    # Environment Variables
    info['Environment Variables'] = run_command('set')
    
    # File Information
    info['Files Information'] = run_command('dir /s')
    
    # Installed Hotfixes
    info['Installed Hotfixes'] = run_command('wmic qfe list')
    
    # Installed Products
    info['Installed Products'] = run_command('wmic product get name')
    
    # Local Group Policy settings
    info['Local Group Policy Settings'] = run_command('gpresult /r')
    
    # Local Groups/Users
    local_groups = run_command('net localgroup')
    local_users = run_command('net user')
    info['Local Groups'] = local_groups
    info['Local Users'] = local_users
    
    # Microsoft Updates
    info['Microsoft Updates'] = run_command('wmic qfe list')
    
    # NTLM Authentication Settings
    info['NTLM Authentication Settings'] = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LMCompatibilityLevel')
    
    # RDP Connections
    info['RDP Connections'] = run_command('reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"')
    
    # Secure Boot Configuration
    info['Secure Boot Configuration'] = run_command('powershell Get-SecureBootPolicy')
    
    # Sysmon Configuration
    info['Sysmon Configuration'] = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SysmonDrv"')
    
    # UAC Policies
    info['UAC Policies'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA')
    
    # PowerShell History
    info['PowerShell History'] = run_command('powershell Get-Content (Get-PSReadlineOption).HistorySavePath')
    
    return info

def collect_network_info():
    """Collects network information and returns a dictionary with the results."""
    info = {}
    
    # ARP Table
    info['ARP Table'] = run_command('arp -a')
    
    # TCP/UDP connections
    info['TCP/UDP Connections'] = run_command('netstat -ano')
    
    # Network Shares
    info['Network Shares'] = run_command('net share')
    
    return info

def generate_report(system_info, network_info):
    """Generates a PDF report from the collected information."""
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt="Windows System & Network Vulnerability Report", ln=True, align="C")
    pdf.ln(10)
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="System Information", ln=True, align="L")
    pdf.ln(5)
    
    for key, value in system_info.items():
        pdf.set_font("Arial", size=10, style='B')
        pdf.cell(0, 10, txt=f"{key}:", ln=True, align="L")
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, value)
        pdf.ln()
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Network Information", ln=True, align="L")
    pdf.ln(5)
    
    for key, value in network_info.items():
        pdf.set_font("Arial", size=10, style='B')
        pdf.cell(0, 10, txt=f"{key}:", ln=True, align="L")
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 10, value)
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
