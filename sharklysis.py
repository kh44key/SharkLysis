#!/usr/bin/env python3

import pyshark
import os
import re
import sys
import hashlib
import magic
import ipaddress
import ssl
import base64
import time
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import warnings
import tempfile
import logging
from bs4 import BeautifulSoup
import geoip2.database
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Suppress pyshark warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IOC_FILE = os.path.join(BASE_DIR, 'iocs.txt')
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
GRAPH_DIR = os.path.join(BASE_DIR, 'graphs')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')
LOG_FILE = os.path.join(BASE_DIR, 'sharklysis.log')

# GeoIP Databases (optional)
GEOIP_ASN_DB = os.path.join(BASE_DIR, 'GeoLite2-ASN.mmdb')
GEOIP_CITY_DB = os.path.join(BASE_DIR, 'GeoLite2-City.mmdb')

# Threat Intelligence Feeds (example)
MALWARE_DOMAINS = os.path.join(BASE_DIR, 'malware_domains.txt')
SUSPICIOUS_IPS = os.path.join(BASE_DIR, 'suspicious_ips.txt')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# ASCII Banner
ASCII_BANNER = f"""{chr(27)}[1;31m

███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗██╗  ██╗   ██╗███████╗██╗███████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████╗███████║███████║██████╔╝█████╔╝ ██║   ╚████╔╝ ███████╗██║███████╗
╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██║    ╚██╔╝  ╚════██║██║╚════██║
███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗██║   ███████║██║███████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝
                                                                          
{chr(27)}[0m
          Advanced PCAP/PCAPNG Analyzer                 
                   By. Saad Ali
"""

def enable_colors():
    """Enable ANSI color support on Windows if needed"""
    if os.name == 'nt':
        os.system('color')

def create_directories():
    """Create necessary directories for reports, graphs, and temp files"""
    for directory in [REPORT_DIR, GRAPH_DIR, TEMP_DIR]:
        os.makedirs(directory, exist_ok=True)
    logging.info("Created required directories")

def validate_pcap(file_path):
    """Validate the input file is a valid PCAP/PCAPNG file"""
    try:
        # Check file magic number
        file_type = magic.from_file(file_path)
        if 'pcap' not in file_type.lower():
            logging.error(f"Invalid file type: {file_type}")
            return False
        
        # Check file size (prevent memory exhaustion)
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
        if file_size > 500:  # 500MB limit
            logging.warning(f"Large file detected ({file_size:.2f}MB). Processing may be slow.")
            
        return True
    except Exception as e:
        logging.error(f"File validation failed: {e}")
        return False

def load_threat_intelligence():
    """Enhanced threat intelligence loading"""
    threat_data = {
        'ips': set(),
        'domains': set(),
        'hashes': set(),
        'ssl_certs': set()
    }
    
    # Load IOCs from multiple sources
    for file_path in [IOC_FILE, MALWARE_DOMAINS, SUSPICIOUS_IPS]:
        if os.path.exists(file_path):
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # IP Addresses
                    try:
                        ipaddress.ip_address(line)
                        threat_data['ips'].add(line)
                        continue
                    except ValueError:
                        pass
                    
                    # Domains
                    if re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', line, re.IGNORECASE):
                        threat_data['domains'].add(line.lower())
                    
                    # SHA256 hashes
                    elif re.match(r'^[a-f0-9]{64}$', line, re.IGNORECASE):
                        threat_data['hashes'].add(line.lower())
                    
                    # SSL fingerprints
                    elif re.match(r'^[a-f0-9]{40}$', line, re.IGNORECASE):  # SHA1
                        threat_data['ssl_certs'].add(line.lower())
    
    logging.info(f"Loaded {len(threat_data['ips'])} malicious IPs, {len(threat_data['domains'])} domains, "
                f"{len(threat_data['hashes'])} hashes, {len(threat_data['ssl_certs'])} SSL certs")
    return threat_data

def detect_malicious_patterns(packet, stats):
    """Enhanced malicious pattern detection"""
    try:
        # SSL/TLS Certificate Analysis
        if hasattr(packet, 'ssl') and hasattr(packet.ssl, 'handshake_certificate'):
            cert = packet.ssl.handshake_certificate
            cert_hash = hashlib.sha1(cert).hexdigest()
            if cert_hash in stats['threat_intel']['ssl_certs']:
                stats['malicious_certs'].add(cert_hash)
        
        # HTTP User-Agent Analysis
        if hasattr(packet, 'http') and hasattr(packet.http, 'user_agent'):
            ua = packet.http.user_agent.lower()
            suspicious_agents = [
                'sqlmap', 'nikto', 'metasploit', 'nessus',
                'wpscan', 'hydra', 'havij', 'zap', 'nmap',
                'dirb', 'gobuster', 'wget', 'curl', 'nikto'
            ]
            if any(agent in ua for agent in suspicious_agents):
                stats['suspicious_user_agents'].append(ua)
        
        # DNS Tunneling Detection
        if hasattr(packet, 'dns'):
            domain = packet.dns.qry_name.lower()
            # Check for long domains (possible tunneling)
            if len(domain) > 50:
                stats['dns_tunneling_candidates'].add(domain)
            # Check for suspicious patterns
            if re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', domain):
                stats['dns_tunneling_candidates'].add(domain)
        
        # SQL Injection Patterns
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            uri = packet.http.request_uri.lower()
            sql_patterns = [
                r'union.*select', r'\d+\s*=\s*\d+', r'1\s*=\s*1',
                r'exec\s*\(', r'waitfor\s*delay', r'--\s*$',
                r'select.*from', r'insert\s+into', r'delete\s+from',
                r'drop\s+table', r'xp_cmdshell'
            ]
            if any(re.search(pattern, uri) for pattern in sql_patterns):
                stats['sql_injection_attempts'].append(uri)
        
        # XSS Patterns
        if hasattr(packet, 'http'):
            xss_patterns = [
                r'<script>', r'javascript:', r'onerror=',
                r'onload=', r'alert\(', r'document\.cookie',
                r'<iframe>', r'<img src=.*>', r'<svg/onload=',
                r'eval\(', r'fromCharCode'
            ]
            http_fields = [
                getattr(packet.http, field, '') 
                for field in ['request_uri', 'file_data', 'referer', 'cookie']
                if hasattr(packet.http, field)
            ]
            for field in http_fields:
                if any(re.search(pattern, field.lower()) for pattern in xss_patterns):
                    stats['xss_attempts'].append(field)
        
        # Malware C2 Patterns
        if hasattr(packet, 'http') and hasattr(packet.http, 'host'):
            host = packet.http.host.lower()
            c2_patterns = [
                r'^[a-z0-9]{16}\.(com|net|org)$',  # DGA-like
                r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$',  # IP as domain
                r'\.ddns\.', r'\.no-ip\.', r'\.dyn\.',  # Dynamic DNS
                r'pastebin\.com', r'github\.com', r'discordapp\.com',
                r'command-and-control', r'c2-server', r'malicious-domain'
            ]
            if any(re.search(pattern, host) for pattern in c2_patterns):
                stats['c2_candidates'].add(host)
    
    except Exception as e:
        logging.debug(f"Error in pattern detection: {e}")

def analyze_tls(packet, stats):
    """Analyze TLS/SSL handshake for security issues"""
    try:
        if hasattr(packet, 'ssl'):
            # Check for weak cipher suites
            if hasattr(packet.ssl, 'handshake_ciphersuite'):
                weak_ciphers = [
                    '0x0004', '0x0005', '0x000a', '0x0013',  # RC4, DES
                    '0x002f', '0x0035', '0xc011', '0xc012',   # Weak TLS
                    '0x0000', '0x0001', '0x0002', '0x0003',  # NULL, IDEA, EXPORT
                    '0x0006', '0x0007', '0x0008', '0x0009',  # EXPORT40, EXPORT56, EXPORT40, EXPORT56
                    '0x000b', '0x000c', '0x000d', '0x000e',  # EXPORT40, EXPORT56, EXPORT40, EXPORT56
                    '0x000f', '0x0010', '0x0011', '0x0012',  # EXPORT40, EXPORT56, EXPORT40, EXPORT56
                    '0x0014', '0x0015', '0x0016', '0x0017',  # EXPORT40, EXPORT56, EXPORT40, EXPORT56
                    '0x0018', '0x0019', '0x001a', '0x001b',  # EXPORT40, EXPORT56, EXPORT40, EXPORT56
                    '0x001c', '0x001d', '0x001e', '0x001f'   # EXPORT40, EXPORT56, EXPORT40, EXPORT56
                ]
                if packet.ssl.handshake_ciphersuite in weak_ciphers:
                    stats['weak_ciphers'].add(packet.ssl.handshake_ciphersuite)
            
            # Check for SSLv3 or TLS 1.0
            if hasattr(packet.ssl, 'record_version'):
                version = packet.ssl.record_version
                if version in ['0x0300', '0x0301']:  # SSLv3, TLS 1.0
                    stats['weak_protocols'].add(version)
            
            # Extract certificate information
            if hasattr(packet.ssl, 'handshake_certificate'):
                cert_data = packet.ssl.handshake_certificate
                try:
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                    # Check certificate expiration
                    if cert.not_valid_after < datetime.now():
                        stats['expired_certs'].add(cert.serial_number)
                    # Check validity period
                    validity = cert.not_valid_after - cert.not_valid_before
                    if validity.days > 825:  # ~2.25 years
                        stats['long_validity_certs'].add(cert.serial_number)
                except Exception as e:
                    logging.debug(f"Certificate parsing error: {e}")
    
    except Exception as e:
        logging.debug(f"TLS analysis error: {e}")

def generate_protocol_chart(protocol_counts, file_path):
    """Generate pie chart for protocol distribution"""
    try:
        plt.figure(figsize=(10, 7))
        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title('Protocol Distribution')
        chart_path = os.path.join(GRAPH_DIR, f"protocols_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        return chart_path
    except Exception as e:
        logging.error(f"Error generating protocol chart: {e}")
        return None

def generate_top_talkers_chart(top_ips, file_path):
    """Generate bar chart for top talkers"""
    try:
        plt.figure(figsize=(12, 6))
        ips, counts = zip(*top_ips)
        plt.bar(ips, counts, color='blue')
        plt.xlabel('IP Address')
        plt.ylabel('Packet Count')
        plt.title('Top Talkers')
        plt.xticks(rotation=45)
        plt.tight_layout()
        chart_path = os.path.join(GRAPH_DIR, f"talkers_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        return chart_path
    except Exception as e:
        logging.error(f"Error generating top talkers chart: {e}")
        return None

def generate_port_activity_chart(port_counts, file_path):
    """Generate bar chart for destination ports"""
    try:
        plt.figure(figsize=(12, 6))
        ports = list(port_counts.keys())
        counts = list(port_counts.values())
        plt.bar(ports, counts, color='green')
        plt.xlabel('Destination Port')
        plt.ylabel('Connection Count')
        plt.title('Destination Port Activity')
        plt.tight_layout()
        chart_path = os.path.join(GRAPH_DIR, f"ports_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        return chart_path
    except Exception as e:
        logging.error(f"Error generating port activity chart: {e}")
        return None

def generate_timeline_chart(timestamps, file_path):
    """Generate timeline of packet activity"""
    try:
        plt.figure(figsize=(12, 6))
        plt.hist(timestamps, bins=50, color='purple', alpha=0.7)
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packet Count')
        plt.title('Packet Timeline Distribution')
        plt.tight_layout()
        chart_path = os.path.join(GRAPH_DIR, f"timeline_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        return chart_path
    except Exception as e:
        logging.error(f"Error generating timeline chart: {e}")
        return None

def generate_network_graph(stats, file_path):
    """Generate network communication graph"""
    try:
        plt.figure(figsize=(12, 8))
        
        # Prepare data
        connections = defaultdict(int)
        for src, dst in stats['ip_connections']:
            connections[(src, dst)] += 1
        
        # Create graph
        max_connections = max(connections.values()) if connections else 1
        for (src, dst), count in connections.items():
            plt.plot([src, dst], [0, 1], linewidth=count/max_connections*5, 
                    color='blue', alpha=0.5)
        
        plt.title('Network Communication Graph', fontweight='bold')
        plt.axis('off')
        
        chart_path = os.path.join(GRAPH_DIR, f"network_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        return chart_path
    except Exception as e:
        logging.error(f"Error generating network graph: {e}")
        return None

def image_to_data_url(image_path):
    """Convert image to data URL for embedding in HTML"""
    if not image_path or not os.path.exists(image_path):
        return ""
    
    try:
        with open(image_path, "rb") as img_file:
            encoded_image = base64.b64encode(img_file.read()).decode('utf-8')
        return f"data:image/png;base64,{encoded_image}"
    except Exception as e:
        logging.error(f"Error converting image to data URL: {e}")
        return ""

def generate_console_report(stats):
    """Generate detailed console report"""
    print("\n" + "="*80)
    print(f"{'PCAP ANALYSIS REPORT':^80}")
    print("="*80)
    
    # File information
    print(f"\n{' File Information ':-^80}")
    print(f"Total Packets: {stats['total_packets']}")
    print(f"Analysis Duration: {stats['analysis_duration']}")
    
    # Protocol distribution
    print(f"\n{' Protocol Distribution ':-^80}")
    for proto, count in stats['protocols'].most_common(10):
        print(f"{proto:<15}: {count} packets ({count/stats['total_packets']*100:.1f}%)")
    
    # Top talkers
    print(f"\n{' Top Talkers ':-^80}")
    for ip, count in stats['src_ips'].most_common(10):
        print(f"{ip:<15}: {count} packets")
    
    # Port activity
    print(f"\n{' Destination Port Activity ':-^80}")
    for port, count in stats['dst_ports'].most_common(10):
        print(f"Port {port:<5}: {count} connections")
    
    # DNS activity
    print(f"\n{' DNS Activity ':-^80}")
    for ip, domains in list(stats['dns_queries'].items())[:10]:
        print(f"{ip:<15} queried {len(domains)} domains")
        if domains:
            print(f"  Sample domains: {', '.join(domains[:3])}")
    
    # Security findings
    if (stats['suspicious_ips'] or stats['malicious_certs'] or 
        stats['dns_tunneling_candidates'] or stats['sql_injection_attempts'] or
        stats['xss_attempts'] or stats['c2_candidates'] or stats['weak_ciphers']):
        
        print(f"\n{' SECURITY FINDINGS ':-^80}")
        
        if stats['suspicious_ips']:
            print(f"\nSuspicious IPs detected ({len(stats['suspicious_ips'])}):")
            for ip in list(stats['suspicious_ips'])[:5]:
                print(f"  - {ip}")
        
        if stats['malicious_certs']:
            print(f"\nMalicious SSL certificates detected ({len(stats['malicious_certs'])}):")
            for cert in list(stats['malicious_certs'])[:3]:
                print(f"  - {cert[:20]}...")
        
        if stats['dns_tunneling_candidates']:
            print(f"\nPossible DNS tunneling domains ({len(stats['dns_tunneling_candidates'])}):")
            for domain in list(stats['dns_tunneling_candidates'])[:5]:
                print(f"  - {domain}")
        
        if stats['sql_injection_attempts']:
            print(f"\nSQL injection patterns detected ({len(stats['sql_injection_attempts'])}):")
            for attempt in stats['sql_injection_attempts'][:3]:
                print(f"  - {attempt[:60]}{'...' if len(attempt) > 60 else ''}")
        
        if stats['xss_attempts']:
            print(f"\nXSS patterns detected ({len(stats['xss_attempts'])}):")
            for attempt in stats['xss_attempts'][:3]:
                print(f"  - {attempt[:60]}{'...' if len(attempt) > 60 else ''}")
        
        if stats['c2_candidates']:
            print(f"\nPossible C2 domains detected ({len(stats['c2_candidates'])}):")
            for domain in list(stats['c2_candidates'])[:5]:
                print(f"  - {domain}")
        
        if stats['weak_ciphers']:
            print(f"\nWeak cipher suites detected ({len(stats['weak_ciphers'])}):")
            for cipher in stats['weak_ciphers']:
                print(f"  - {cipher}")
        
        if stats['weak_protocols']:
            print(f"\nWeak protocols detected ({len(stats['weak_protocols'])}):")
            for protocol in stats['weak_protocols']:
                print(f"  - {protocol}")
        
        if stats['suspicious_user_agents']:
            print(f"\nSuspicious user agents detected ({len(stats['suspicious_user_agents'])}):")
            # FIX: Convert to list before slicing
            for ua in list(set(stats['suspicious_user_agents']))[:5]:
                print(f"  - {ua}")
    
    print("\n" + "="*80)
    print(f"{' REPORT COMPLETE ':^80}")
    print("="*80)

def create_html_report(stats, graphs, filename):
    """Generate comprehensive security report with embedded images"""
    try:
        # Create HTML structure
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SharkLysis Security Report</title>
    <style>
        :root {{
            --primary: #2c3e50;
            --secondary: #3498db;
            --danger: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
            --light: #ecf0f1;
            --dark: #34495e;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f7fa;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 30px 20px;
            text-align: center;
        }}
        
        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .report-meta {{
            display: flex;
            justify-content: space-between;
            background-color: var(--light);
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
        }}
        
        .meta-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .meta-item strong {{
            color: var(--dark);
            font-size: 0.9rem;
        }}
        
        .meta-item span {{
            font-weight: bold;
            font-size: 1.1rem;
        }}
        
        section {{
            padding: 25px;
            border-bottom: 1px solid #eee;
        }}
        
        section:last-child {{
            border-bottom: none;
        }}
        
        h2 {{
            color: var(--primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--secondary);
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 20px;
            transition: transform 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
        }}
        
        .card h3 {{
            color: var(--secondary);
            margin-bottom: 15px;
        }}
        
        .chart-container {{
            width: 100%;
            height: 250px;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        
        .chart-container img {{
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
        }}
        
        .stats-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        .stats-table th, .stats-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        
        .stats-table th {{
            background-color: var(--light);
            color: var(--dark);
            font-weight: 600;
        }}
        
        .stats-table tr:hover {{
            background-color: rgba(52, 152, 219, 0.05);
        }}
        
        .security-alert {{
            background-color: #fff3f3;
            border-left: 4px solid var(--danger);
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 4px 4px 0;
        }}
        
        .security-alert h4 {{
            color: var(--danger);
            margin-bottom: 8px;
        }}
        
        .security-warning {{
            background-color: #fff8e6;
            border-left: 4px solid var(--warning);
        }}
        
        .security-warning h4 {{
            color: var(--warning);
        }}
        
        .security-info {{
            background-color: #e8f4fd;
            border-left: 4px solid var(--secondary);
        }}
        
        .security-info h4 {{
            color: var(--secondary);
        }}
        
        .threat-level-high {{
            background-color: rgba(231, 76, 60, 0.1);
            color: var(--danger);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        .threat-level-medium {{
            background-color: rgba(243, 156, 18, 0.1);
            color: var(--warning);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        .threat-level-low {{
            background-color: rgba(52, 152, 219, 0.1);
            color: var(--secondary);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            background-color: var(--dark);
            color: white;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SharkLysis Security Report</h1>
            <p>Comprehensive Network Traffic Analysis</p>
        </header>
        
        <div class="report-meta">
            <div class="meta-item">
                <strong>Report Generated</strong>
                <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="meta-item">
                <strong>PCAP File</strong>
                <span>{os.path.basename(stats['file_path'])}</span>
            </div>
            <div class="meta-item">
                <strong>Analysis Duration</strong>
                <span>{stats['analysis_duration']}</span>
            </div>
        </div>
        
        <section>
            <h2>Overview</h2>
            <div class="grid">
                <div class="card">
                    <h3>Traffic Summary</h3>
                    <table class="stats-table">
                        <tr>
                            <td>Total Packets</td>
                            <td>{stats['total_packets']}</td>
                        </tr>
                        <tr>
                            <td>Unique Source IPs</td>
                            <td>{len(stats['src_ips'])}</td>
                        </tr>
                        <tr>
                            <td>Unique Connections</td>
                            <td>{len(stats['ip_connections'])}</td>
                        </tr>
                        <tr>
                            <td>DNS Queries</td>
                            <td>{sum(len(v) for v in stats['dns_queries'].values())}</td>
                        </tr>
                    </table>
                </div>
                
                <div class="card">
                    <h3>Security Summary</h3>
                    <table class="stats-table">
                        <tr>
                            <td>Suspicious IPs</td>
                            <td>{len(stats['suspicious_ips'])}</td>
                        </tr>
                        <tr>
                            <td>Malicious Certificates</td>
                            <td>{len(stats['malicious_certs'])}</td>
                        </tr>
                        <tr>
                            <td>SQL Injection Attempts</td>
                            <td>{len(stats['sql_injection_attempts'])}</td>
                        </tr>
                        <tr>
                            <td>XSS Attempts</td>
                            <td>{len(stats['xss_attempts'])}</td>
                        </tr>
                    </table>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Traffic Analysis</h2>
            <div class="grid">
                <div class="card">
                    <h3>Protocol Distribution</h3>
                    <div class="chart-container">
                        <img src="{image_to_data_url(graphs.get('Protocol Distribution'))}" alt="Protocol Distribution">
                    </div>
                    <table class="stats-table">
                        <tr>
                            <th>Protocol</th>
                            <th>Packets</th>
                            <th>Percentage</th>
                        </tr>
        """
        
        # Add protocol data
        for proto, count in stats['protocols'].most_common(10):
            percentage = count / stats['total_packets'] * 100
            html += f"""
                        <tr>
                            <td>{proto}</td>
                            <td>{count}</td>
                            <td>{percentage:.1f}%</td>
                        </tr>
            """
        
        html += """
                    </table>
                </div>
                
                <div class="card">
                    <h3>Top Talkers</h3>
                    <div class="chart-container">
                        <img src="{image_to_data_url(graphs.get('Top Talkers'))}" alt="Top Talkers">
                    </div>
                    <table class="stats-table">
                        <tr>
                            <th>IP Address</th>
                            <th>Packets</th>
                        </tr>
        """
        
        # Add top talkers
        for ip, count in stats['src_ips'].most_common(10):
            html += f"""
                        <tr>
                            <td>{ip}</td>
                            <td>{count}</td>
                        </tr>
            """
        
        html += """
                    </table>
                </div>
                
                <div class="card">
                    <h3>Port Activity</h3>
                    <div class="chart-container">
                        <img src="{image_to_data_url(graphs.get('Port Activity'))}" alt="Port Activity">
                    </div>
                    <table class="stats-table">
                        <tr>
                            <th>Port</th>
                            <th>Connections</th>
                        </tr>
        """
        
        # Add port activity
        for port, count in stats['dst_ports'].most_common(10):
            html += f"""
                        <tr>
                            <td>{port}</td>
                            <td>{count}</td>
                        </tr>
            """
        
        html += """
                    </table>
                </div>
                
                <div class="card">
                    <h3>Traffic Timeline</h3>
                    <div class="chart-container">
                        <img src="{image_to_data_url(graphs.get('Traffic Timeline'))}" alt="Traffic Timeline">
                    </div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Network Communications</h2>
            <div class="chart-container">
                <img src="{image_to_data_url(graphs.get('Network Graph'))}" alt="Network Graph" style="max-height: 500px;">
            </div>
        </section>
        
        <section>
            <h2>Security Findings</h2>
        """
        
        # Add security findings
        if stats['suspicious_ips']:
            html += """
            <div class="security-alert">
                <h4><span class="threat-level-high">HIGH</span> Suspicious IPs Detected</h4>
                <p>The following IP addresses were found in threat intelligence databases:</p>
                <ul>
            """
            for ip in stats['suspicious_ips']:
                html += f"<li>{ip}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['malicious_certs']:
            html += f"""
            <div class="security-alert">
                <h4><span class="threat-level-high">HIGH</span> Malicious SSL Certificates Detected</h4>
                <p>{len(stats['malicious_certs'])} malicious SSL certificates were identified.</p>
            </div>
            """
        
        if stats['sql_injection_attempts']:
            html += f"""
            <div class="security-alert">
                <h4><span class="threat-level-high">HIGH</span> SQL Injection Attempts Detected</h4>
                <p>{len(stats['sql_injection_attempts'])} SQL injection patterns were identified in HTTP requests.</p>
                <p>Sample patterns:</p>
                <ul>
            """
            for attempt in stats['sql_injection_attempts'][:3]:
                html += f"<li>{attempt[:120]}{'...' if len(attempt) > 120 else ''}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['xss_attempts']:
            html += f"""
            <div class="security-alert">
                <h4><span class="threat-level-high">HIGH</span> XSS Attempts Detected</h4>
                <p>{len(stats['xss_attempts'])} XSS patterns were identified in HTTP requests.</p>
                <p>Sample patterns:</p>
                <ul>
            """
            for attempt in stats['xss_attempts'][:3]:
                html += f"<li>{attempt[:120]}{'...' if len(attempt) > 120 else ''}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['c2_candidates']:
            html += f"""
            <div class="security-alert">
                <h4><span class="threat-level-high">HIGH</span> Possible C2 Domains Detected</h4>
                <p>{len(stats['c2_candidates'])} domains show characteristics of command-and-control servers.</p>
                <ul>
            """
            for domain in list(stats['c2_candidates'])[:5]:
                html += f"<li>{domain}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['dns_tunneling_candidates']:
            html += f"""
            <div class="security-warning">
                <h4><span class="threat-level-medium">MEDIUM</span> Possible DNS Tunneling</h4>
                <p>{len(stats['dns_tunneling_candidates'])} domains show characteristics of DNS tunneling.</p>
                <ul>
            """
            for domain in list(stats['dns_tunneling_candidates'])[:5]:
                html += f"<li>{domain}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['weak_ciphers']:
            html += f"""
            <div class="security-warning">
                <h4><span class="threat-level-medium">MEDIUM</span> Weak Cipher Suites Detected</h4>
                <p>{len(stats['weak_ciphers'])} weak cipher suites were identified in TLS communications.</p>
                <ul>
            """
            for cipher in stats['weak_ciphers']:
                html += f"<li>{cipher}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['weak_protocols']:
            html += f"""
            <div class="security-warning">
                <h4><span class="threat-level-medium">MEDIUM</span> Weak Protocols Detected</h4>
                <p>{len(stats['weak_protocols'])} weak protocols were identified in TLS communications.</p>
                <ul>
            """
            for protocol in stats['weak_protocols']:
                html += f"<li>{protocol}</li>"
            html += """
                </ul>
            </div>
            """
        
        if stats['suspicious_user_agents']:
            html += f"""
            <div class="security-info">
                <h4><span class="threat-level-low">LOW</span> Suspicious User Agents</h4>
                <p>{len(stats['suspicious_user_agents'])} suspicious user agents were detected.</p>
                <ul>
            """
            # FIX: Convert to list before slicing
            for ua in list(set(stats['suspicious_user_agents']))[:5]:
                html += f"<li>{ua}</li>"
            html += """
                </ul>
            </div>
            """
        
        # If no security findings
        if not any([stats['suspicious_ips'], stats['malicious_certs'], stats['dns_tunneling_candidates'],
                  stats['sql_injection_attempts'], stats['xss_attempts'], stats['c2_candidates'],
                  stats['weak_ciphers'], stats['weak_protocols'], stats['suspicious_user_agents']]):
            html += """
            <div class="security-info">
                <h4>No Critical Security Issues Detected</h4>
                <p>No high-risk security threats were identified in the network traffic.</p>
            </div>
            """
        
        html += """
        </section>
        
        <footer>
            <p>Report generated by SharkLysis - Advanced Network Security Analysis</p>
            <p>Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
        """
        
        # Write final report
        with open(filename, 'w') as f:
            f.write(html)
        
        logging.info(f"Generated comprehensive security report: {filename}")
        return True
    except Exception as e:
        logging.error(f"Error generating security report: {e}")
        return False

def analyze_pcap(file_path):
    """Enhanced PCAP analysis with comprehensive security checks"""
    start_time = datetime.now()
    logging.info(f"Starting analysis of: {file_path}")
    
    if not validate_pcap(file_path):
        logging.error("Invalid PCAP file")
        return
    
    # Initialize stats with enhanced security tracking
    stats = {
        'file_path': file_path,
        'protocols': Counter(),
        'src_ips': Counter(),
        'dst_ports': Counter(),
        'dns_queries': defaultdict(list),
        'suspicious_ips': set(),
        'credentials': [],
        'total_packets': 0,
        'packet_times': [],
        'threat_intel': load_threat_intelligence(),
        'security_alerts': [],
        'malicious_certs': set(),
        'suspicious_user_agents': [],
        'dns_tunneling_candidates': set(),
        'sql_injection_attempts': [],
        'xss_attempts': [],
        'c2_candidates': set(),
        'weak_ciphers': set(),
        'weak_protocols': set(),
        'expired_certs': set(),
        'long_validity_certs': set(),
        'ip_connections': set(),
        'geolocation_data': defaultdict(dict)
    }

    try:
        # Use temporary file for large PCAPs
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB
                logging.info("Large file detected, using temporary storage")
                with open(file_path, 'rb') as src:
                    for chunk in iter(lambda: src.read(1024*1024), b''):  # 1MB chunks
                        temp_file.write(chunk)
                temp_file.flush()
                capture_path = temp_file.name
            else:
                capture_path = file_path
            
            capture = pyshark.FileCapture(
                capture_path,
                only_summaries=False,
                display_filter='tcp or udp or icmp or dns or http or ssl'
            )
            
            for pkt in capture:
                stats['total_packets'] += 1
                stats['packet_times'].append(float(pkt.sniff_timestamp))
                
                try:
                    # Basic protocol analysis
                    proto = pkt.highest_layer
                    stats['protocols'][proto] += 1
                    
                    # IP analysis
                    if hasattr(pkt, 'ip'):
                        src = pkt.ip.src
                        dst = pkt.ip.dst
                        stats['src_ips'][src] += 1
                        stats['ip_connections'].add((src, dst))
                        
                        # Check threat intelligence
                        if src in stats['threat_intel']['ips'] or dst in stats['threat_intel']['ips']:
                            stats['suspicious_ips'].add(src if src in stats['threat_intel']['ips'] else dst)
                    
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
                        if domain.lower() in stats['threat_intel']['domains']:
                            stats['suspicious_ips'].add(pkt.ip.src)
                    
                    # Enhanced security analysis
                    detect_malicious_patterns(pkt, stats)
                    analyze_tls(pkt, stats)
                    
                except AttributeError:
                    continue
                except Exception as e:
                    logging.debug(f"Packet analysis error: {e}")
    
    except Exception as e:
        logging.error(f"Analysis error: {e}")
    finally:
        capture.close()
    
    # Calculate analysis duration
    stats['analysis_duration'] = str(datetime.now() - start_time)
    
    # Generate visualizations
    graphs = {}
    try:
        graphs['Protocol Distribution'] = generate_protocol_chart(
            dict(stats['protocols'].most_common(10)), file_path)
        
        graphs['Top Talkers'] = generate_top_talkers_chart(
            stats['src_ips'].most_common(10), file_path)
        
        graphs['Port Activity'] = generate_port_activity_chart(
            dict(stats['dst_ports'].most_common(10)), file_path)
        
        if stats['packet_times']:
            graphs['Traffic Timeline'] = generate_timeline_chart(
                stats['packet_times'], file_path)
        
        graphs['Network Graph'] = generate_network_graph(stats, file_path)
    except Exception as e:
        logging.error(f"Visualization error: {e}")
    
    # Generate console report
    generate_console_report(stats)
    
    # Generate comprehensive report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"sharklysis_report_{os.path.basename(file_path)}_{timestamp}.html"
    report_path = os.path.join(REPORT_DIR, report_name)
    
    try:
        create_html_report(stats, graphs, report_path)
        logging.info(f"Analysis complete. Report generated: {report_path}")
    except Exception as e:
        logging.error(f"Report generation failed: {e}")

if __name__ == '__main__':
    try:
        enable_colors()
        create_directories()
        print(ASCII_BANNER)
        
        if len(sys.argv) != 2:
            print("\nUsage: python sharklysis.py <file.pcap|file.pcapng>")
            sys.exit(1)
        
        file_path = os.path.abspath(sys.argv[1])
        if not os.path.exists(file_path):
            print(f"\n[!] File not found: {file_path}")
            sys.exit(1)
        
        # Security check - prevent directory traversal
        if '../' in file_path or not file_path.endswith(('.pcap', '.pcapng')):
            print("\n[!] Invalid file path or extension")
            sys.exit(1)
        
        analyze_pcap(file_path)
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        sys.exit(1)
