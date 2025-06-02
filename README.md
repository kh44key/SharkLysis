

![SharkLysis Logo](https://github.com/kh44key/SharkLysis/blob/main/assests/banner.png)  
# SharkLysis - Advanced PCAP/PCAPNG Analyzer

SharkLysis is a Python-based tool designed to analyze PCAP/PCAPNG files for network traffic insights and security threats. It leverages `pyshark` for packet parsing, threat intelligence for identifying malicious activity, and generates detailed HTML reports and visualizations.

## Features
- **Packet Analysis**: Parse PCAP/PCAPNG files to extract protocols, IP connections, DNS queries, and more.
- **Threat Detection**: Identify malicious IPs, domains, SSL certificates, SQL injection attempts, XSS attempts, and potential C2 communications.
- **TLS Analysis**: Detect weak ciphers, protocols, and expired or overly long-validity certificates.
- **Geolocation**: Map IP addresses to geographic locations using GeoIP databases.
- **WHOIS Lookup**: Retrieve domain registration details for DNS queries.
- **Visualizations**: Generate charts (protocol distribution, top talkers, port activity, DNS queries, timeline) and network graphs.
- **HTML Reports**: Comprehensive, styled HTML reports with embedded charts and security findings.

## Requirements
- Python 3.8+
- Tshark (Wireshark command-line tool) installed and accessible
- GeoIP databases (`GeoLite2-City.mmdb.gz`, `GeoLite2-ASN.mmdb`) from MaxMind
- Dependencies listed in `requirements.txt`

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/sharklysis.git
   cd sharklysis
   ```

2. **Set Up a Virtual Environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Tshark**:
   - On Ubuntu/Debian: `sudo apt-get install tshark`
   - On macOS: `brew install wireshark`
   - On Windows: Install Wireshark and ensure `tshark` is in your PATH.

5. **Prepare Data Files**:
   - Place `iocs.txt`, `malware_domains.txt`, and `suspicious_ips.txt` in the `data/` directory.
   - Download and place `GeoLite2-City.mmdb.gz` and `GeoLite2-ASN.mmdb` in the `data/` directory (available from [MaxMind](https://www.maxmind.com)).

## Usage
Run the script with a PCAP/PCAPNG file as an argument:
```bash
python sharklysis.py path/to/capture.pcap
```

- The script validates the input file and processes it.
- Outputs include:
  - Console report summarizing traffic and security findings.
  - HTML report in the `reports/` directory (e.g., `sharklysis_report_capture_YYYYMMDD_HHMMSS.html`).
  - Charts in the `graphs/` directory (e.g., `protocols_capture.png`, `talkers_capture.png`).
  - Logs in `sharklysis.log`.

## Project Structure
```
sharklysis/
├── sharklysis.py              # Main script
├── requirements.txt           # Python dependencies
├── README.md                 # This file
├── .gitignore                # Git ignore file
├── data/                     # Threat intelligence and GeoIP data
│   ├── iocs.txt
│   ├── malware_domains.txt
│   ├── suspicious_ips.txt
│   ├── GeoLite2-City.mmdb.gz
│   └── GeoLite2-ASN.mmdb
├── reports/                  # Generated HTML reports
├── graphs/                   # Generated charts
└── temp/                     # Temporary files
```

## Notes
- **GeoIP Databases**: Ensure `GeoLite2-City.mmdb.gz` is decompressed to `GeoLite2-City.mmdb` if required by your system.
- **Large Files**: For PCAP files >100MB, temporary storage is used to optimize memory usage.
- **Rate Limits**: WHOIS queries include a 1-second delay to avoid rate limiting.
- **Logging**: Detailed logs are saved to `sharklysis.log` for debugging.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Authors
- Saad Ali
- Muhammad Saad Hanif

## Acknowledgments
- Built with [pyshark](https://github.com/KimiNewt/pyshark), [matplotlib](https://matplotlib.org/), and [networkx](https://networkx.org/).
- GeoIP data provided by [MaxMind](https://www.maxmind.com).

