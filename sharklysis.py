#!/usr/bin/env python3

import pyshark
import os
import re
import sys
import hashlib
import magic
import base64
import time
import tempfile
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import networkx as nx
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import geoip2.database
import whois
from tld import get_tld

# Configure logging with INFO level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'sharklysis.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Directory Setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
GRAPH_DIR = os.path.join(BASE_DIR, 'graphs')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')

# Threat Intelligence and GeoIP Files
IOC_FILE = os.path.join(BASE_DIR, 'iocs.txt')
MALWARE_DOMAINS = os.path.join(BASE_DIR, 'malware_domains.txt')
SUSPICIOUS_IPS = os.path.join(BASE_DIR, 'suspicious_ips.txt')
GEOIP_ASN_DB = os.path.join(BASE_DIR, 'GeoLite2-ASN.mmdb')
GEOIP_CITY_DB = os.path.join(BASE_DIR, 'GeoLite2-City.mmdb')

# ASCII Banner
ASCII_BANNER = f"""{chr(27)}[1;31m

███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗██╗  ██╗   ██╗███████╗██╗███████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██║  ╚██╗ ██╔╝██╔════╝██║██╔════╝
███████╗███████║███████║██████╔╝█████╔╝ ██║   ╚████╔╝ ███████╗██║███████╗                                                                                    
╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██║    ╚██╔╝  ╚════██║██║╚════██║                                                                                    
███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗██║   ███████║██║███████║                                                                                    
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚═╝╚══════╝                                                                                    
                                                                                                                                                             
                    Advanced PCAP/PCAPNG Analyzer                                                                                                                      
                      By. Saad Ali & Saad Hanif                                                                                                                            
                                                                                                                                                             
{chr(27)}[0m
"""

def enable_colors():
    if os.name == 'nt':
        os.system('color')

def create_directories():
    for directory in [REPORT_DIR, GRAPH_DIR, TEMP_DIR]:
        os.makedirs(directory, exist_ok=True)
    logger.info("Created required directories")

def validate_pcap(file_path):
    try:
        file_type = magic.from_file(file_path)
        if 'pcap' not in file_type.lower():
            logger.error(f"Invalid file type: {file_type}")
            return False
        file_size = os.path.getsize(file_path) / (1024 * 1024)
        if file_size > 500:
            logger.warning(f"Large file detected ({file_size:.2f}MB). Processing may be slow.")
        return True
    except Exception as e:
        logger.error(f"File validation failed: {e}")
        return False

def load_threat_intelligence():
    threat_data = {
        'ips': set(),
        'domains': set(),
        'hashes': set(),
        'ssl_certs': set()
    }
    domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    hash_pattern = r'^[a-f0-9]{64}$'
    ssl_pattern = r'^[a-f0-9]{40}$'
    for file_path in [IOC_FILE, MALWARE_DOMAINS, SUSPICIOUS_IPS]:
        if not os.path.exists(file_path):
            logger.warning(f"Threat intelligence file not found: {file_path}")
            continue
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    ipaddress.ip_address(line)
                    threat_data['ips'].add(line)
                    continue
                except ValueError:
                    pass
                if re.match(domain_pattern, line, re.IGNORECASE):
                    threat_data['domains'].add(line.lower())
                elif re.match(hash_pattern, line, re.IGNORECASE):
                    threat_data['hashes'].add(line.lower())
                elif re.match(ssl_pattern, line, re.IGNORECASE):
                    threat_data['ssl_certs'].add(line.lower())
    logger.info(f"Loaded {len(threat_data['ips'])} malicious IPs, {len(threat_data['domains'])} domains, "
                f"{len(threat_data['hashes'])} hashes, {len(threat_data['ssl_certs'])} SSL certs")
    return threat_data

def detect_malicious_patterns(packet, stats):
    try:
        if hasattr(packet, 'ssl') and hasattr(packet.ssl, 'handshake_certificate'):
            cert_hash = hashlib.sha1(packet.ssl.handshake_certificate).hexdigest()
            if cert_hash in stats['threat_intel']['ssl_certs']:
                stats['malicious_certs'].add(cert_hash)
                logger.info(f"Malicious SSL cert detected: {cert_hash}")
        if hasattr(packet, 'http') and hasattr(packet.http, 'user_agent'):
            ua = packet.http.user_agent.lower()
            suspicious_agents = ['sqlmap', 'nikto', 'metasploit', 'nessus', 'wpscan', 'hydra',
                                'havij', 'zap', 'nmap', 'dirb', 'gobuster', 'wget', 'curl']
            if any(agent in ua for agent in suspicious_agents):
                stats['suspicious_user_agents'].append(ua)
                logger.info(f"Suspicious user agent detected: {ua}")
        if hasattr(packet, 'dns'):
            domain = packet.dns.qry_name.lower()
            if len(domain) > 50 or re.search(r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', domain):
                stats['dns_tunneling_candidates'].add(domain)
                logger.info(f"Possible DNS tunneling: {domain}")
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            uri = packet.http.request_uri.lower()
            sql_patterns = [r'union.*select', r'\d+\s*=\s*\d+', r'1\s*=\s*1', r'exec\s*\(',
                            r'waitfor\s*delay', r'--\s*$', r'select.*from', r'insert\s+into',
                            r'delete\s+from', r'drop\s+table', r'xp_cmdshell']
            if any(re.search(pattern, uri) for pattern in sql_patterns):
                stats['sql_injection_attempts'].append(uri)
                logger.info(f"SQL injection attempt detected: {uri}")
        if hasattr(packet, 'http'):
            xss_patterns = [r'<script>', r'javascript:', r'onerror=', r'onload=', r'alert\(',
                            r'document\.cookie', r'<iframe>', r'<img src=.*>', r'<svg/onload=',
                            r'eval\(', r'fromCharCode']
            http_fields = [getattr(packet.http, field, '') for field in ['request_uri', 'file_data', 'referer', 'cookie'] if hasattr(packet.http, field)]
            for field in http_fields:
                if any(re.search(pattern, field.lower()) for pattern in xss_patterns):
                    stats['xss_attempts'].append(field)
                    logger.info(f"XSS attempt detected: {field}")
        if hasattr(packet, 'http') and hasattr(packet.http, 'host'):
            host = packet.http.host.lower()
            c2_patterns = [r'^[a-z0-9]{16}\.(com|net|org)$', r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                           r'\.ddns\.', r'\.no-ip\.', r'\.dyn\.', r'pastebin\.com', r'github\.com',
                           r'discordapp\.com', r'command-and-control', r'c2-server', r'malicious-domain']
            if any(re.search(pattern, host) for pattern in c2_patterns):
                stats['c2_candidates'].add(host)
                logger.info(f"Possible C2 domain: {host}")
    except Exception as e:
        logger.debug(f"Error in pattern detection: {e}")

def analyze_tls(packet, stats):
    try:
        if hasattr(packet, 'ssl'):
            if hasattr(packet.ssl, 'handshake_ciphersuite'):
                weak_ciphers = ['0x0004', '0x0005', '0x000a', '0x0013', '0x002f', '0x0035',
                                '0xc011', '0xc012', '0x0000', '0x0001', '0x0002', '0x0003']
                if packet.ssl.handshake_ciphersuite in weak_ciphers:
                    stats.setdefault('weak_ciphers', set()).add(packet.ssl.handshake_ciphersuite)
                    logger.info(f"Weak cipher detected: {packet.ssl.handshake_ciphersuite}")
            if hasattr(packet.ssl, 'record_version'):
                if packet.ssl.record_version in ['0x0300', '0x0301']:
                    stats.setdefault('weak_protocols', set()).add(packet.ssl.record_version)
                    logger.info(f"Weak protocol detected: {packet.ssl.record_version}")
            if hasattr(packet.ssl, 'handshake_certificate'):
                cert_data = packet.ssl.handshake_certificate
                try:
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                    if cert.not_valid_after < datetime.now():
                        stats.setdefault('expired_certs', set()).add(cert.serial_number)
                        logger.info(f"Expired cert detected: {cert.serial_number}")
                    validity = (cert.not_valid_after - cert.not_valid_before).days
                    if validity > 825:
                        stats.setdefault('long_validity_certs', set()).add(cert.serial_number)
                        logger.info(f"Long validity cert detected: {cert.serial_number}")
                except Exception as e:
                    logger.debug(f"Certificate parsing error: {e}")
    except Exception as e:
        logger.debug(f"TLS analysis error: {e}")

def get_geolocation(ip):
    try:
        if os.path.exists(GEOIP_CITY_DB):
            with geoip2.database.Reader(GEOIP_CITY_DB) as reader:
                response = reader.city(ip)
                return {
                    'city': response.city.name,
                    'country': response.country.name,
                    'lat': response.location.latitude,
                    'lon': response.location.longitude
                }
        logger.warning("GeoIP City database not found")
        return {}
    except Exception as e:
        logger.debug(f"GeoIP error for {ip}: {e}")
        return {}

def get_whois_info(domain, queried_domains):
    if domain in queried_domains:
        logger.info(f"Skipping WHOIS query for {domain} (already queried)")
        return queried_domains[domain]

    try:
        # Extract the TLD for subdomains
        try:
            res = get_tld(domain, as_object=True)
            domain_to_query = res.fld  # Use the registered domain (e.g., google.com)
        except Exception:
            domain_to_query = domain  # Fallback to original domain if TLD extraction fails

        logger.info(f"Querying WHOIS for domain: {domain_to_query}")
        time.sleep(1)  # Add delay to avoid rate limits
        w = whois.whois(domain_to_query)  # Corrected to whois.whois
        if w is None:
            logger.error(f"No WHOIS data returned for {domain_to_query}")
            result = {'registrar': 'N/A', 'creation_date': 'N/A', 'expiration_date': 'N/A'}
        else:
            registrar = getattr(w, 'registrar', 'N/A')
            creation_date = getattr(w, 'creation_date', 'N/A')
            expiration_date = getattr(w, 'expiration_date', 'N/A')
            logger.info(f"WHOIS result for {domain_to_query}: Registrar={registrar}, Creation={creation_date}, Expiration={expiration_date}")
            result = {
                'registrar': registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date
            }
    except Exception as e:
        logger.error(f"Whois error for {domain_to_query}: {e}")
        result = {'registrar': 'N/A', 'creation_date': 'N/A', 'expiration_date': 'N/A'}

    queried_domains[domain] = result
    return result

def generate_protocol_chart(protocol_counts, file_path):
    try:
        plt.figure(figsize=(8, 6))
        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title('Protocol Distribution')
        chart_path = os.path.join(GRAPH_DIR, f"protocols_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        logger.info(f"Generated chart: {chart_path}")
        return chart_path
    except Exception as e:
        logger.error(f"Error generating protocol chart: {e}")
        return None

def generate_top_talkers_chart(top_ips, file_path):
    try:
        plt.figure(figsize=(10, 5))
        ips, counts = zip(*top_ips)
        plt.bar(ips, counts, color='blue')
        plt.xlabel('IP Address')
        plt.ylabel('Packet Count')
        plt.xticks(rotation=45, ha='right')
        plt.title('Top Talkers')
        chart_path = os.path.join(GRAPH_DIR, f"talkers_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        logger.info(f"Generated chart: {chart_path}")
        return chart_path
    except Exception as e:
        logger.error(f"Error generating top talkers chart: {e}")
        return None

def generate_port_activity_chart(port_counts, file_path):
    try:
        plt.figure(figsize=(10, 5))
        ports = list(port_counts.keys())
        counts = list(port_counts.values())
        plt.bar(ports, counts, color='green')
        plt.xlabel('Destination Port')
        plt.ylabel('Connection Count')
        plt.title('Destination Port Activity')
        chart_path = os.path.join(GRAPH_DIR, f"ports_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        logger.info(f"Generated chart: {chart_path}")
        return chart_path
    except Exception as e:
        logger.error(f"Error generating port activity chart: {e}")
        return None

def generate_dns_chart(dns_queries, file_path):
    try:
        plt.figure(figsize=(10, 5))
        domains = [d for domains in dns_queries.values() for d in domains]
        domain_counts = Counter(domains).most_common(10)
        domains, counts = zip(*domain_counts)
        plt.bar(domains, counts, color='orange')
        plt.xlabel('Domain')
        plt.ylabel('Query Count')
        plt.xticks(rotation=45, ha='right')
        plt.title('Top DNS Queries')
        chart_path = os.path.join(GRAPH_DIR, f"dns_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        logger.info(f"Generated chart: {chart_path}")
        return chart_path
    except Exception as e:
        logger.error(f"Error generating DNS chart: {e}")
        return None

def generate_timeline_chart(timestamps, file_path):
    try:
        plt.figure(figsize=(10, 5))
        plt.hist(timestamps, bins=50, color='purple', alpha=0.7)
        plt.xlabel('Time (seconds)')
        plt.ylabel('Packet Count')
        plt.title('Packet Timeline Distribution')
        chart_path = os.path.join(GRAPH_DIR, f"timeline_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path)
        plt.close()
        logger.info(f"Generated chart: {chart_path}")
        return chart_path
    except Exception as e:
        logger.error(f"Error generating timeline chart: {e}")
        return None

def generate_network_graph(stats, file_path):
    try:
        plt.figure(figsize=(10, 8))
        G = nx.Graph()
        for src, dst in stats['ip_connections']:
            G.add_node(src, size=300)
            G.add_node(dst, size=300)
            G.add_edge(src, dst, weight=1)
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightblue', node_size=500,
                font_size=8, font_weight='bold', edge_color='purple', alpha=0.6)
        plt.title('Network Communication Graph', fontweight='bold')
        plt.axis('off')
        chart_path = os.path.join(GRAPH_DIR, f"network_{os.path.basename(file_path)}.png")
        plt.savefig(chart_path, dpi=100)
        plt.close()
        logger.info(f"Generated chart: {chart_path}")
        return chart_path
    except Exception as e:
        logger.error(f"Error generating network graph: {e}")
        return None

def image_to_data_url(image_path):
    if not image_path or not os.path.exists(image_path):
        logger.error(f"Image path invalid or not found: {image_path}")
        return '<p class="no-data">Chart unavailable</p>'
    try:
        with open(image_path, "rb") as img_file:
            encoded = base64.b64encode(img_file.read()).decode('utf-8')
            logger.info(f"Successfully encoded image: {image_path} (length: {len(encoded)})")
            return f'<img src="data:image/png;base64,{encoded}" alt="Chart">'
    except Exception as e:
        logger.error(f"Error converting image to data URL: {e}")
        return '<p class="no-data">Chart unavailable</p>'

def generate_console_report(stats):
    print("\n" + "="*80)
    print(f"{'PCAP ANALYSIS REPORT':^80}")
    print("="*80)
    print(f"\n{'Traffic Summary':-^80}")
    print(f"Total Packets: {stats['total_packets']}")
    print(f"Analysis Duration: {stats['analysis_duration']}")
    print(f"Unique Countries: {len(stats['unique_countries'])}" if stats['unique_countries'] else "Unique Countries: N/A")
    print(f"\n{'Security Findings':-^80}")
    if stats['suspicious_ips']:
        print(f"Suspicious IPs: {len(stats['suspicious_ips'])}")
    if stats['malicious_certs']:
        print(f"Malicious Certificates: {len(stats['malicious_certs'])}")
    if stats['dns_tunneling_candidates']:
        print(f"DNS Tunneling Domains: {len(stats['dns_tunneling_candidates'])}")
    if stats['sql_injection_attempts']:
        print(f"SQL Injection Attempts: {len(stats['sql_injection_attempts'])}")
    if stats['xss_attempts']:
        print(f"XSS Attempts: {len(stats['xss_attempts'])}")
    if stats['c2_candidates']:
        print(f"C2 Domains: {len(stats['c2_candidates'])}")
    if stats['weak_ciphers']:
        print(f"Weak Ciphers: {len(stats['weak_ciphers'])}")
    if stats['weak_protocols']:
        print(f"Weak Protocols: {len(stats['weak_protocols'])}")
    if stats['expired_certs']:
        print(f"Expired Certificates: {len(stats['expired_certs'])}")
    if stats['long_validity_certs']:
        print(f"Long Validity Certificates: {len(stats['long_validity_certs'])}")
    if stats['suspicious_user_agents']:
        print(f"Suspicious User Agents: {len(stats['suspicious_user_agents'])}")
    print(f"\n{'WHOIS Summary':-^80}")
    registrar_list = ", ".join(stats['unique_registrars']) if stats['unique_registrars'] else "N/A"
    print(f"Unique Registrars: {len(stats['unique_registrars'])} ({registrar_list})")
    print("\n" + "="*80)
    print(f"{'REPORT COMPLETE':^80}")
    print("="*80)

def create_html_report(stats, graphs, filename):
    current_time = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p') + " PKT"
    security_issues_keys = ['sql_injection_attempts', 'xss_attempts', 'c2_candidates', 'malicious_certs', 'suspicious_ips']
    security_issues = [k for k in security_issues_keys if stats.get(k)]
    security_summary = f"{len(security_issues)} high-priority issues detected" if security_issues else '<p class="no-data">No high-priority security issues detected</p>'
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SharkLysis Security Report</title>
    <style>
        :root {{ --primary: #2c3e50; --secondary: #3498db; --danger: #e74c3c; --warning: #f39c12; --success: #27ae60; --light: #ecf0f1; --dark: #34495e; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f7fa; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }}
        header {{ background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; padding: 30px; text-align: center; }}
        header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        .report-meta {{ display: flex; justify-content: space-between; background: var(--light); padding: 15px; border-bottom: 1px solid #ddd; }}
        .meta-item {{ display: flex; flex-direction: column; }}
        .meta-item strong {{ color: var(--dark); font-size: 0.9rem; }}
        .meta-item span {{ font-weight: bold; font-size: 1.1rem; }}
        section {{ padding: 25px; border-bottom: 1px solid #eee; }}
        section:last-child {{ border-bottom: none; }}
        h2 {{ color: var(--primary); margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid var(--secondary); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 20px; }}
        .card h3 {{ color: var(--secondary); margin-bottom: 15px; }}
        .chart-container {{ width: 100%; height: 300px; display: flex; justify-content: center; align-items: center; }}
        .chart-container img {{ max-width: 100%; max-height: 100%; object-fit: contain; }}
        .stats-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        .stats-table th, .stats-table td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }}
        .stats-table th {{ background: var(--light); color: var(--dark); font-weight: 600; }}
        .security-alert {{ background: #fff3f3; border-left: 4px solid var(--danger); padding: 15px; margin: 15px 0; border-radius: 0 4px 4px 0; }}
        .security-warning {{ background: #fff8e6; border-left: 4px solid var(--warning); }}
        .security-info {{ background: #e8f4fd; border-left: 4px solid var(--secondary); }}
        .threat-level-high {{ background: rgba(231,76,60,0.1); color: var(--danger); padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
        .threat-level-medium {{ background: rgba(243,156,18,0.1); color: var(--warning); padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
        .threat-level-low {{ background: rgba(52,152,219,0.1); color: var(--secondary); padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
        footer {{ text-align: center; padding: 20px; background: var(--dark); color: white; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header><h1>SharkLysis Security Report</h1><p>Comprehensive Network Traffic Analysis</p></header>
        <div class="report-meta">
            <div class="meta-item"><strong>Report Generated</strong><span>{current_time}</span></div>
            <div class="meta-item"><strong>PCAP File</strong><span>{os.path.basename(stats['file_path'])}</span></div>
            <div class="meta-item"><strong>Analysis Duration</strong><span>{stats['analysis_duration']}</span></div>
        </div>
        <section><h2>Overview</h2><div class="grid">
            <div class="card"><h3>Traffic Summary</h3><table class="stats-table">
                <tr><td>Total Packets</td><td>{stats['total_packets']}</td></tr>
                <tr><td>Unique Source IPs</td><td>{len(stats['src_ips'])}</td></tr>
                <tr><td>Unique Connections</td><td>{len(stats['ip_connections'])}</td></tr>
                <tr><td>DNS Queries</td><td>{sum(len(v) for v in stats['dns_queries'].values())}</td></tr>
                <tr><td>Unique Countries</td><td>{len(stats['unique_countries'])} ({', '.join(stats['unique_countries']) if stats['unique_countries'] else 'N/A'})</td></tr>
            </table></div>
            <div class="card"><h3>Security Summary</h3>
                {security_summary}
            </div></div></section>
        <section><h2>Traffic Analysis</h2><div class="grid">
            <div class="card"><h3>Protocol Distribution</h3><div class="chart-container">{image_to_data_url(graphs.get('Protocol Distribution'))}</div></div>
            <div class="card"><h3>Top Talkers</h3><div class="chart-container">{image_to_data_url(graphs.get('Top Talkers'))}</div></div>
            <div class="card"><h3>Port Activity</h3><div class="chart-container">{image_to_data_url(graphs.get('Port Activity'))}</div></div>
            <div class="card"><h3>DNS Queries</h3><div class="chart-container">{image_to_data_url(graphs.get('DNS Queries'))}</div></div>
            <div class="card"><h3>Traffic Timeline</h3><div class="chart-container">{image_to_data_url(graphs.get('Traffic Timeline'))}</div></div>
        </div></section>
        <section><h2>Network Communications</h2><div class="chart-container">{image_to_data_url(graphs.get('Network Graph'))}</div></section>
        <section><h2>Geolocation Summary</h2>
            <div class="card"><p>Unique countries detected: {len(stats['unique_countries'])} ({', '.join(stats['unique_countries']) if stats['unique_countries'] else 'N/A'})</p></div>
        </section>
        <section><h2>WHOIS Summary</h2>
            <div class="card"><p>Unique registrars detected: {len(stats['unique_registrars'])} ({', '.join(stats['unique_registrars']) if stats['unique_registrars'] else 'N/A'})</p></div>
        </section>
        <section><h2>Security Findings</h2>
            {''.join([f'<div class="security-alert"><h4><span class="threat-level-high">HIGH</span> {k.replace("_", " ").title()} Detected</h4><p>{len(v)} instances found.</p><ul>{("".join([f"<li>{i[:50]}{'...' if len(i) > 50 else ''}</li>" for i in v[:3]])) if isinstance(v, list) else "".join([f"<li>{i}</li>" for i in list(v)[:3]])}</ul></div>' for k, v in stats.items() if k in ['sql_injection_attempts', 'xss_attempts', 'c2_candidates', 'malicious_certs', 'suspicious_ips'] and v])}
            {''.join([f'<div class="security-warning"><h4><span class="threat-level-medium">MEDIUM</span> {k.replace("_", " ").title()}</h4><p>{len(v)} instances found.</p><ul>{("".join([f"<li>{i[:50]}{'...' if len(i) > 50 else ''}</li>" for i in v[:3]])) if isinstance(v, list) else "".join([f"<li>{i}</li>" for i in list(v)[:3]])}</ul></div>' for k, v in stats.items() if k in ['dns_tunneling_candidates', 'weak_ciphers', 'weak_protocols', 'expired_certs', 'long_validity_certs'] and v])}
            {''.join([f'<div class="security-info"><h4><span class="threat-level-low">LOW</span> {k.replace("_", " ").title()}</h4><p>{len(v)} instances found.</p><ul>{("".join([f"<li>{i[:50]}{'...' if len(i) > 50 else ''}</li>" for i in v[:3]])) if isinstance(v, list) else "".join([f"<li>{i}</li>" for i in list(v)[:3]])}</ul></div>' for k, v in stats.items() if k in ['suspicious_user_agents'] and v])}
            {('<div class="security-info"><h4>No Critical Issues</h4><p>No high-risk threats detected.</p></div>' if not any([stats.get(k) for k in ['sql_injection_attempts', 'xss_attempts', 'c2_candidates', 'malicious_certs', 'suspicious_ips']]) else '')}
        </section>
        <footer><p>Report generated by SharkLysis - Advanced Network Security Analysis</p><p>Generated at {current_time}</p></footer>
    </div>
</body>
</html>"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        logger.info(f"Generated security report: {filename}")
    except Exception as e:
        logger.error(f"Failed to write HTML report: {e}")

def analyze_pcap(file_path):
    start_time = datetime.now()
    logger.info(f"Starting analysis of: {file_path}")
    if not validate_pcap(file_path):
        logger.error("Invalid PCAP file")
        return
    stats = {
        'file_path': file_path,
        'protocols': Counter(),
        'src_ips': Counter(),
        'dst_ports': Counter(),
        'dns_queries': defaultdict(list),
        'suspicious_ips': set(),
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
        'geolocation_data': defaultdict(dict),
        'whois_data': defaultdict(dict),
        'unique_countries': set(),
        'unique_registrars': set(),
        'total_packets': 0,
        'packet_times': [],
        'threat_intel': load_threat_intelligence()
    }
    queried_domains = {}  # Cache for WHOIS queries to avoid duplicates
    capture = None
    try:
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                logger.info("Large file detected, using temporary storage")
                with open(file_path, 'rb') as src:
                    for chunk in iter(lambda: src.read(1024*1024), b''):
                        temp_file.write(chunk)
                temp_file.flush()
                capture_path = temp_file.name
            else:
                capture_path = file_path
            capture = pyshark.FileCapture(capture_path, only_summaries=False, display_filter='tcp or udp or icmp or dns or http or ssl')
            for pkt in capture:
                stats['total_packets'] += 1
                stats['packet_times'].append(float(pkt.sniff_timestamp))
                proto = pkt.highest_layer
                stats['protocols'][proto] += 1
                if hasattr(pkt, 'ip'):
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    stats['src_ips'][src] += 1
                    stats['ip_connections'].add((src, dst))
                    if src in stats['threat_intel']['ips'] or dst in stats['threat_intel']['ips']:
                        stats['suspicious_ips'].add(src if src in stats['threat_intel']['ips'] else dst)
                        logger.info(f"Suspicious IP detected: {src if src in stats['threat_intel']['ips'] else dst}")
                    geo_src = get_geolocation(src)
                    geo_dst = get_geolocation(dst)
                    stats['geolocation_data'][src].update(geo_src)
                    stats['geolocation_data'][dst].update(geo_dst)
                    if geo_src.get('country'):
                        stats['unique_countries'].add(geo_src['country'])
                    if geo_dst.get('country'):
                        stats['unique_countries'].add(geo_dst['country'])
                if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'dstport'):
                    stats['dst_ports'][pkt.tcp.dstport] += 1
                if hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                    domain = pkt.dns.qry_name
                    logger.debug(f"Found DNS query for domain: {domain}")
                    stats['dns_queries'][pkt.ip.src].append(domain)
                    if domain.lower() in stats['threat_intel']['domains']:
                        stats['suspicious_ips'].add(pkt.ip.src)
                        logger.info(f"Suspicious domain queried: {domain} by {pkt.ip.src}")
                    whois_info = get_whois_info(domain, queried_domains)
                    stats['whois_data'][domain].update(whois_info)
                    if whois_info.get('registrar') and whois_info['registrar'] != 'N/A':
                        stats['unique_registrars'].add(whois_info['registrar'])
                detect_malicious_patterns(pkt, stats)
                analyze_tls(pkt, stats)
    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user, saving partial results")
    except Exception as e:
        logger.error(f"Analysis error: {e}")
    finally:
        if capture:
            capture.close()
    stats['analysis_duration'] = str(datetime.now() - start_time)
    graphs = {
        'Protocol Distribution': generate_protocol_chart(dict(stats['protocols'].most_common(10)), file_path),
        'Top Talkers': generate_top_talkers_chart(stats['src_ips'].most_common(10), file_path),
        'Port Activity': generate_port_activity_chart(dict(stats['dst_ports'].most_common(10)), file_path),
        'DNS Queries': generate_dns_chart(stats['dns_queries'], file_path),
        'Traffic Timeline': generate_timeline_chart(stats['packet_times'], file_path),
        'Network Graph': generate_network_graph(stats, file_path)
    }
    generate_console_report(stats)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"sharklysis_report_{os.path.basename(file_path)}_{timestamp}.html"
    report_path = os.path.join(REPORT_DIR, report_name)
    create_html_report(stats, graphs, report_path)
    logger.info(f"Analysis complete. Report generated: {report_path}")

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
        if '../' in file_path or not file_path.endswith(('.pcap', '.pcapng')):
            print("\n[!] Invalid file path or extension")
            sys.exit(1)
        analyze_pcap(file_path)
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)
