#!/usr/bin/env python3

import pyshark
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

IOC_FILE = os.path.join(os.path.dirname(__file__), 'iocs.txt')
REPORT_DIR = os.path.join(os.path.dirname(__file__), 'reports')

ASCII_BANNER = f"""{chr(27)}[1;31m

███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗██╗  ██╗   ██╗███████╗██╗███████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████╗███████║███████║██████╔╝█████╔╝ ██║   ╚████╔╝ ███████╗██║███████╗
╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██║    ╚██╔╝  ╚════██║██║╚════██║
███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗██║   ███████║██║███████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝
                                                                          
{chr(27)}[0m
          Advanced PCAP/PCAPNG Analyzer                 
By. Saad Ali, Saad Hanif, Abdullah Tarar, Ali Oun
"""

def enable_colors():
    """Enable ANSI color support on Windows if needed"""
    if os.name == 'nt':
        os.system('color')

def load_iocs():
    """Load Indicators of Compromise from file"""
    ips = set()
    domains = set()
    if os.path.exists(IOC_FILE):
        with open(IOC_FILE) as f:
            for line in f:
                line = line.strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    ips.add(line)
                elif '.' in line:
                    domains.add(line)
    return ips, domains

def generate_html_report(data, filename):
    """Generate HTML report from analysis data"""
    html = f"""<html>
    <head>
        <title>Sharklysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #2c3e50; }}
            .section {{ margin-bottom: 30px; }}
            .alert {{ color: #e74c3c; font-weight: bold; }}
            pre {{ background: #f5f5f5; padding: 10px; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h1>Sharklysis Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <hr>"""
    
    for section, content in data.items():
        html += f"""
        <div class="section">
            <h2>{section}</h2>
            <pre>{content}</pre>
        </div>
        <hr>"""
    
    html += "</body></html>"
    
    with open(filename, "w") as f:
        f.write(html)

def analyze_pcap(file_path):
    """Analyze PCAP/PCAPNG file"""
    print(f"\n[*] Analyzing: {file_path}")
    print("[*] This may take some time for large files...\n")
    
    try:
        capture = pyshark.FileCapture(file_path, only_summaries=False)
    except Exception as e:
        print(f"[!] Error opening file: {e}")
        return

    # Initialize counters
    stats = {
        'protocols': Counter(),
        'src_ips': Counter(),
        'dst_ports': Counter(),
        'dns_queries': defaultdict(list),
        'suspicious_ips': set(),
        'credentials': [],
        'total_packets': 0
    }

    ioc_ips, ioc_domains = load_iocs()

    try:
        for pkt in capture:
            stats['total_packets'] += 1
            
            try:
                # Protocol analysis
                proto = pkt.highest_layer
                stats['protocols'][proto] += 1

                # IP analysis
                if hasattr(pkt, 'ip'):
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    stats['src_ips'][src] += 1
                    
                    # Check for IOCs
                    if src in ioc_ips or dst in ioc_ips:
                        stats['suspicious_ips'].add(src if src in ioc_ips else dst)

                # Port analysis
                if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'dstport'):
                    stats['dst_ports'][pkt.tcp.dstport] += 1

                # Credential detection
                if hasattr(pkt, 'http') and hasattr(pkt.http, 'authorization'):
                    stats['credentials'].append(pkt.http.authorization)

                # DNS analysis
                if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                    domain = pkt.dns.qry_name
                    stats['dns_queries'][pkt.ip.src].append(domain)
                    if domain in ioc_domains:
                        stats['suspicious_ips'].add(pkt.ip.src)

            except AttributeError:
                continue

    except Exception as e:
        print(f"[!] Error during analysis: {e}")
    finally:
        capture.close()

    # Generate report data
    report_data = {
        "File Information": f"File: {file_path}\nTotal Packets: {stats['total_packets']}",
        "Protocol Distribution": "\n".join(f"{k}: {v}" for k, v in stats['protocols'].most_common()),
        "Top Talkers": "\n".join(f"{ip}: {count} packets" for ip, count in stats['src_ips'].most_common(5)),
        "Common Destination Ports": "\n".join(f"Port {port}: {count} connections" for port, count in stats['dst_ports'].most_common(5))
    }

    # Check for anomalies
    anomalies = []
    
    # Port scan detection
    if any(count > 100 for count in stats['dst_ports'].values()):
        msg = "Possible port scanning detected (multiple connections to different ports)"
        anomalies.append(msg)
        report_data["Port Scan Detection"] = msg
    
    # DNS tunneling detection
    if any(len(domains) > 20 for domains in stats['dns_queries'].values()):
        msg = "Possible DNS tunneling detected (excessive DNS queries from single source)"
        anomalies.append(msg)
        report_data["DNS Tunneling Detection"] = msg
    
    # Credential alerts
    if stats['credentials']:
        msg = f"Credentials found in plaintext ({len(stats['credentials'])} instances)"
        anomalies.append(msg)
        report_data["Credentials Found"] = "\n".join(stats['credentials'])
    
    # IOC alerts
    if stats['suspicious_ips']:
        msg = f"IOC matches found ({len(stats['suspicious_ips'])} suspicious IPs)"
        anomalies.append(msg)
        report_data["IOC Matches"] = "\n".join(stats['suspicious_ips'])

    # Print summary to console
    print("\n=== Analysis Summary ===")
    print(f"Total packets processed: {stats['total_packets']}")
    print(f"Top protocol: {stats['protocols'].most_common(1)[0][0]}")
    print(f"Top source IP: {stats['src_ips'].most_common(1)[0][0]}")
    
    if anomalies:
        print("\n[!] Security Alerts:")
        for alert in anomalies:
            print(f"  - {alert}")
    else:
        print("\n[+] No security anomalies detected")

    # Generate HTML report
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"sharklysis_report_{os.path.basename(file_path)}_{timestamp}.html"
    report_path = os.path.join(REPORT_DIR, report_name)
    
    try:
        generate_html_report(report_data, report_path)
        print(f"\n[+] HTML report generated: {report_path}")
    except Exception as e:
        print(f"\n[!] Error generating report: {e}")

def main():
    enable_colors()
    print(ASCII_BANNER)
    
    if len(sys.argv) != 2:
        print("\nUsage: python sharklysis.py <file.pcap|file.pcapng>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"\n[!] File not found: {file_path}")
        sys.exit(1)
    
    analyze_pcap(file_path)

if __name__ == '__main__':
    main()
