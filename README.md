# WiFi Network Device Scanner

A powerful Python tool for discovering and analyzing devices on your home network. Perfect for network administrators, IoT enthusiasts, and security-conscious users who want to know what's connected to their WiFi.

## Features

- **Smart Network Detection**: Automatically detects your network range or allows custom specification
- **Multi-Method Discovery**: Uses ICMP ping, ARP scanning, and aggressive mesh network techniques
- **Enhanced Mesh Support**: Special algorithms for Eero, Google Nest, and other mesh networks
- **Device Intelligence**: Identifies device types (routers, computers, phones, IoT devices, printers)
- **MAC Vendor Lookup**: Discovers device manufacturers using online databases
- **Port Scanning**: Optional scanning for open ports and service identification
- **Multiple Export Formats**: JSON, CSV, and HTML reports with color-coded device types
- **Device Tracking**: Monitor network changes over time
- **Fast & Efficient**: Multi-threaded scanning with customizable timeout and thread count

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic network scan
python wifi_scanner.py

# Scan specific network range
python wifi_scanner.py -n 192.168.1.0/24

# Enhanced scan for mesh networks (recommended for Eero users)
python wifi_scanner.py --arp-scan --aggressive

# Full scan with port detection
python wifi_scanner.py -p --show-services

# Export results to different formats
python wifi_scanner.py --export html
python wifi_scanner.py --export csv --export-file my_network.csv
```

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/home-network-discovery.git
   cd home-network-discovery
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the scanner:**
   ```bash
   python wifi_scanner.py
   ```

## Command Line Options

```
usage: wifi_scanner.py [-h] [-n NETWORK] [-t TIMEOUT] [-T THREADS] [-p] [-s SAVE] [-q] 
                       [--export {json,csv,html}] [--export-file EXPORT_FILE] [--show-services] 
                       [--history] [--arp-scan] [--aggressive] [--detect-networks]

Options:
  -h, --help            Show help message and exit
  -n, --network         Network range to scan (e.g., 192.168.1.0/24)
  -t, --timeout         Ping timeout in seconds (default: 1.0)
  -T, --threads         Number of scanning threads (default: 50)
  -p, --ports           Scan for open ports on discovered devices
  -s, --save            Save results to JSON file
  -q, --quiet           Suppress progress output
  --export {json,csv,html}    Export results in specified format
  --export-file         Specify export filename
  --show-services       Show detailed service information for open ports
  --history             Show device change history from previous scans
  --arp-scan            Use ARP scanning (finds devices that don't respond to ping)
  --aggressive          Use aggressive scanning for mesh networks
  --detect-networks     Show all detected network interfaces and ranges
```

## Mesh Network Support (Eero Users)

If you're using an Eero mesh network and only seeing one device (usually 192.168.1.254), use these enhanced scanning options:

```bash
# Enhanced mesh network scanning
python wifi_scanner.py --arp-scan --aggressive -n 192.168.1.0/24

# Detect all network ranges and scan the best one
python wifi_scanner.py --detect-networks --arp-scan
```

The tool automatically detects mesh network isolation and uses specialized techniques to discover devices that may be hidden from traditional ping scans.

## Output Examples

### Basic Scan Output
```
================================================================================
NETWORK SCAN RESULTS - 23 devices found
================================================================================
IP Address: 192.168.7.1
Hostname:   Unknown
MAC:        4C:01:43:80:7A:02
Vendor:     TP-Link Technologies
Device Type: Router
Ping Time:  2.1ms
Last Seen:  2025-01-15T10:30:45.123456
----------------------------------------
IP Address: 192.168.7.28
Hostname:   Unknown
MAC:        20:DF:B9:A4:DF:75
Vendor:     Google, Inc.
Device Type: IoT Device
Ping Time:  15.2ms
Last Seen:  2025-01-15T10:30:47.654321
```

### HTML Export Features
- Color-coded device types for easy identification
- Sortable tables for better data analysis
- Responsive design for mobile viewing
- Professional formatting for reports

## Understanding Device Types

The scanner intelligently categorizes devices based on various signals:

- **Router**: Network gateway devices, access points
- **Computer**: Desktops, laptops, servers
- **Mobile**: Smartphones, tablets
- **Printer**: Network printers, scanners
- **IoT Device**: Smart home devices, sensors, cameras
- **Unknown**: Devices that couldn't be categorized

## Troubleshooting

### Common Issues

**Q: Only finding one device on Eero network**
A: Use `--arp-scan --aggressive` flags. Eero mesh networks often isolate devices from ping discovery.

**Q: Scan is very slow**
A: Reduce timeout with `-t 0.5` or decrease threads with `-T 25` for slower networks.

**Q: Getting permission errors**
A: Some features may require administrator/root privileges, especially ARP scanning.

**Q: "No devices found" on known active network**
A: Try `--detect-networks` to see available networks, then specify the correct range with `-n`.

### Network-Specific Tips

- **Eero/Mesh Networks**: Always use `--arp-scan --aggressive`
- **Corporate Networks**: May have ICMP disabled; try `--arp-scan`
- **Guest Networks**: Often isolated; limited device discovery expected
- **VPN Connections**: May affect local network detection

## Security Considerations

This tool performs active network scanning which:
- Only scans your local network by default
- Uses standard networking protocols (ICMP, ARP)
- Does not attempt to access or modify device configurations
- Can be detected by network monitoring systems

Always ensure you have permission to scan the networks you target.

## Performance Tips

- **Fast scans**: Use `-t 0.5 -T 100` for responsive networks
- **Thorough scans**: Use `--arp-scan --aggressive -p` for complete discovery
- **Large networks**: Increase timeout `-t 2.0` for networks with 200+ devices
- **Save bandwidth**: Use `-q` to reduce output on slow connections

## Advanced Usage

### Scanning Multiple Networks
```bash
# Scan specific range
python wifi_scanner.py -n 10.0.0.0/24

# Auto-detect and scan all networks
python wifi_scanner.py --detect-networks
```

### Monitoring Network Changes
```bash
# Regular scans to track changes
python wifi_scanner.py --history
```

### Professional Reporting
```bash
# Generate comprehensive HTML report
python wifi_scanner.py -p --show-services --export html --export-file network_audit.html
```

## Dependencies

- **Python 3.7+**: Required for modern language features
- **requests**: For MAC vendor lookups (optional but recommended)
- **Standard library modules**: subprocess, socket, ipaddress, concurrent.futures

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

MIT License - see LICENSE file for details.

---

**Note**: This tool is designed for legitimate network administration and security purposes. Always respect network policies and obtain proper authorization before scanning networks you don't own.
