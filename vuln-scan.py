import argparse
import os
import subprocess
from fpdf import FPDF

def collect_system_info():
    print("[+] Collecting system-level information...\n")

    # Get OS Info
    os_info = subprocess.run(["systeminfo"], capture_output=True, text=True)
    print("OS Information:\n" + os_info.stdout)

    # Get Installed Hotfixes
    hotfixes = subprocess.run(["wmic", "qfe", "list", "brief"], capture_output=True, text=True)
    print("\nInstalled Hotfixes:\n" + hotfixes.stdout)

    # Get Installed Products
    installed_products = subprocess.run(["wmic", "product", "get", "name,version"], capture_output=True, text=True)
    print("\nInstalled Products:\n" + installed_products.stdout)

    # Get Windows Defender Status
    defender_status = subprocess.run(["powershell", "Get-MpComputerStatus"], capture_output=True, text=True)
    print("\nWindows Defender Status:\n" + defender_status.stdout)

    return {
        "OS Information": os_info.stdout,
        "Installed Hotfixes": hotfixes.stdout,
        "Installed Products": installed_products.stdout,
        "Windows Defender Status": defender_status.stdout
    }

def collect_network_info():
    print("[+] Collecting network-level information...\n")

    # Get ARP table
    arp_table = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    print("ARP Table:\n" + arp_table.stdout)

    # Get current network connections (TCP and UDP)
    netstat = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
    print("\nActive Connections:\n" + netstat.stdout)

    # Get network profiles
    network_profiles = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True)
    print("\nNetwork Profiles:\n" + network_profiles.stdout)

    # List Open Ports (Using Powershell)
    open_ports = subprocess.run(["powershell", "Get-NetTCPConnection"], capture_output=True, text=True)
    print("\nOpen Ports:\n" + open_ports.stdout)

    return {
        "ARP Table": arp_table.stdout,
        "Active Connections": netstat.stdout,
        "Network Profiles": network_profiles.stdout,
        "Open Ports": open_ports.stdout
    }

def search_exploits():
    print("[+] Searching for open-source exploits...\n")
    
    # Placeholder for actual exploit search
    # You can implement API calls to sources like ExploitDB or NVD
    exploits = [
        "Exploit 1: Remote Code Execution (CVE-2021-12345)",
        "Exploit 2: Privilege Escalation (CVE-2022-54321)"
    ]
    
    for exploit in exploits:
        print(exploit)
    
    return exploits

def generate_report(output_format, report_path, system_data, network_data, exploit_data):
    if output_format == "pdf":
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Windows Vulnerability Report", ln=True, align="C")
        
        # Add System Information
        pdf.cell(200, 10, txt="System Information", ln=True)
        for key, value in system_data.items():
            pdf.multi_cell(0, 10, txt=f"{key}:\n{value}\n")
        
        # Add Network Information
        pdf.cell(200, 10, txt="Network Information", ln=True)
        for key, value in network_data.items():
            pdf.multi_cell(0, 10, txt=f"{key}:\n{value}\n")
        
        # Add Exploit Information
        pdf.cell(200, 10, txt="Exploit Information", ln=True)
        for exploit in exploit_data:
            pdf.cell(200, 10, txt=f"{exploit}", ln=True)

        pdf_output_path = os.path.join(report_path, "vulnerability_report.pdf")
        pdf.output(pdf_output_path)
        print(f"[+] PDF report generated at {pdf_output_path}")
    
    elif output_format == "html":
        html_output_path = os.path.join(report_path, "vulnerability_report.html")
        with open(html_output_path, 'w') as f:
            f.write("<html><body><h1>Windows Vulnerability Report</h1>")
            
            # Add System Information
            f.write("<h2>System Information</h2>")
            for key, value in system_data.items():
                f.write(f"<h3>{key}</h3><pre>{value}</pre>")
            
            # Add Network Information
            f.write("<h2>Network Information</h2>")
            for key, value in network_data.items():
                f.write(f"<h3>{key}</h3><pre>{value}</pre>")
            
            # Add Exploit Information
            f.write("<h2>Exploit Information</h2>")
            for exploit in exploit_data:
                f.write(f"<p>{exploit}</p>")

            f.write("</body></html>")
        print(f"[+] HTML report generated at {html_output_path}")
    
    else:
        print("[!] Invalid output format specified. Please choose either 'pdf' or 'html'.")

def cli():
    parser = argparse.ArgumentParser(description="Windows Vulnerability Scanner CLI Tool")

    # Add arguments for scan options
    parser.add_argument(
        '-s', '--system', action='store_true', help='Scan system-level vulnerabilities'
    )
    parser.add_argument(
        '-n', '--network', action='store_true', help='Scan network-level vulnerabilities'
    )
    parser.add_argument(
        '-e', '--exploit', action='store_true', help='Search for available open-source exploits'
    )
    parser.add_argument(
        '-o', '--output', type=str, help='Specify output file format (pdf or html)', default="html"
    )
    parser.add_argument(
        '-r', '--report', type=str, help='Path to save the report file', default=os.getcwd()
    )
    parser.add_argument(
        '--all', action='store_true', help='Run all scans (system, network, and exploit search)'
    )
    
    # Parse arguments from CLI
    args = parser.parse_args()

    system_data, network_data, exploit_data = {}, {}, []
    
    # Execute corresponding actions
    if args.system:
        system_data = collect_system_info()
    if args.network:
        network_data = collect_network_info()
    if args.exploit:
        exploit_data = search_exploits()
    if args.all:
        system_data = collect_system_info()
        network_data = collect_network_info()
        exploit_data = search_exploits()

    # Generate the report
    generate_report(args.output, args.report, system_data, network_data, exploit_data)

if __name__ == "__main__":
    cli()
