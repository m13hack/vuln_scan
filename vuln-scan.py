import os
import subprocess
import wmi
from fpdf import FPDF
import datetime
import sys
import traceback
import time

def run_command(command, timeout=60, capture_output=True):
    """Run a command and capture its output or return the error with a timeout."""
    try:
        start_time = time.time()
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        while True:
            if process.poll() is not None:
                # Command finished
                output, error = process.communicate()
                if error:
                    return f"Error: {error}"
                return output

            # Check for timeout
            if time.time() - start_time > timeout:
                process.terminate()
                return f"Command '{command}' timed out after {timeout} seconds."

            time.sleep(1)  # Avoid CPU hogging by sleeping for 1 second

    except subprocess.CalledProcessError as e:
        return f"Error executing command '{command}': {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

def collect_system_info():
    """Collects system information and returns a dictionary with the results."""
    info = {}

    print("[+] Collecting basic OS information...")
    info['OS'] = run_command('systeminfo', timeout=30)

    print("[+] Collecting .NET versions...")
    info['.NET Versions'] = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP" /s /v Version', timeout=30)

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

    print("[+] Collecting TCP/UDP connections...")
    info['TCP/UDP Connections'] = run_command('netstat -ano', timeout=30)

    print("[+] Collecting network shares...")
    info['Network Shares'] = run_command('net share', timeout=30)

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
