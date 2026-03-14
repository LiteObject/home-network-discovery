#!/usr/bin/env python3
"""
WiFi Network Device Scanner

A comprehensive CLI tool to discover and analyze devices on your home network.
Performs network scanning using ping, gathers device information through ARP,
and provides detailed reports with MAC vendor identification.

Author: LiteObject
License: MIT
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import ssl
import struct
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    print("Warning: requests module not found. MAC vendor lookup will be disabled.")
    requests = None

try:
    from zeroconf import Zeroconf, ServiceBrowser, IPVersion  # type: ignore[import-untyped]

    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False


# ============================================================================
# NetworkScanner Class - Main Implementation
# ============================================================================


class NetworkScanner:
    """
    A comprehensive network scanner for discovering devices on local networks.

    This class provides functionality to:
    - Auto-detect or manually specify network ranges
    - Ping hosts to check availability
    - Retrieve MAC addresses and hostnames
    - Perform port scanning
    - Lookup MAC vendor information
    - Generate detailed reports

    Attributes:
        network_range (str): The network CIDR range to scan (e.g., '192.168.1.0/24')
        timeout (float): Ping timeout in seconds
        devices (Dict): Dictionary storing discovered device information
        mac_vendors (Dict): Cache for MAC vendor lookups to avoid repeated API calls
    """

    def __init__(
        self,
        network_range: Optional[str] = None,
        timeout: float = 1.0,
        max_threads: int = 50,
        verbose: bool = False,
        args=None,
    ):
        """
        Initialize the NetworkScanner.

        Args:
            network_range: Network CIDR range to scan. If None, auto-detects the range.
            timeout: Ping timeout in seconds (default: 1.0)
            max_threads: Maximum number of scanning threads (default: 50)
            verbose: Enable verbose output (default: False)
            args: Command line arguments namespace for enhanced features
        """
        self.network_range = network_range or self._get_network_range()
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.args = args or argparse.Namespace(
            arp_scan=False,
            aggressive=False,
            track_changes=False,
            scan_ports=False,
            detect_networks=False,
            ports=False,
            enrich=False,
        )
        self.devices = {}  # Stores discovered device information
        self.mac_vendors = {}  # Cache for vendor lookups
        self.history_file = "network_scan_history.json"  # Device history storage
        self.known_devices = {}  # User-defined device names and types
        self.last_scan_file = None  # Track last scan file for changes
        self.mdns_services = {}  # mDNS services keyed by IP
        self.ssdp_devices = {}  # SSDP/UPnP info keyed by IP

    def _get_network_range(self) -> str:
        """
        Auto-detect the network range for scanning.
        Enhanced for mesh networks and multiple interfaces.

        Attempts multiple methods to determine the local network range:
        1. Parse default gateway from system routing table
        2. Use socket connection to determine local IP
        3. Check multiple network interfaces
        4. Fall back to common home network range

        Returns:
            str: Network range in CIDR notation (e.g., '192.168.1.0/24')
        """
        detected_networks = []

        try:
            # Method 1: Try to detect multiple network interfaces
            detected_networks = self._detect_all_networks()
            if detected_networks:
                print(f"Detected networks: {', '.join(detected_networks)}")
                # For now, use the first non-localhost network
                for network in detected_networks:
                    if not network.startswith("127.") and not network.startswith(
                        "169.254."
                    ):
                        return network

            # Method 2: Get default gateway from routing table
            if platform.system() == "Windows":
                # Enhanced Windows network detection
                return self._detect_windows_network()
            else:
                # Use ip route command on Linux/macOS
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        if "via" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                gateway = parts[2]
                                # Assume /24 subnet (common for home networks)
                                network = ".".join(gateway.split(".")[:-1]) + ".0/24"
                                return network

                # Method 3: Fallback using socket connection to public DNS
                # This determines our local IP by connecting to external service
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))  # Connect to Google DNS
                local_ip = s.getsockname()[0]
                s.close()

                # Assume /24 subnet based on local IP
                network = ".".join(local_ip.split(".")[:-1]) + ".0/24"
                return network

        except (subprocess.CalledProcessError, OSError, socket.error, IndexError) as e:
            print(f"Warning: Could not auto-detect network range: {e}")

        # Try common Eero and mesh network ranges
        common_ranges = [
            "192.168.1.0/24",
            "192.168.0.0/24",
            "192.168.4.0/24",
            "192.168.7.0/24",
            "10.0.0.0/24",
            "172.16.0.0/24",
        ]

        print("Trying common network ranges...")
        for range_test in common_ranges:
            try:
                # Quick test ping to gateway
                network = ipaddress.IPv4Network(range_test)
                gateway = str(network.network_address + 1)  # Usually .1
                if self._ping_host(gateway):
                    print(
                        f"Found active gateway at {gateway}, using range {range_test}"
                    )
                    return range_test
            except Exception:
                continue

        return "192.168.1.0/24"  # Safe fallback for most home networks

    def _detect_all_networks(self) -> List[str]:
        """
        Detect all available network interfaces and their ranges.

        Returns:
            List[str]: List of network ranges in CIDR notation
        """
        networks = []

        try:
            if platform.system() == "Windows":
                # Windows: Use ipconfig /all
                result = subprocess.run(
                    ["ipconfig", "/all"], capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    networks.extend(self._parse_windows_ipconfig(result.stdout))
            else:
                # Linux/macOS: Use ip addr or ifconfig
                try:
                    result = subprocess.run(
                        ["ip", "addr"], capture_output=True, text=True, check=False
                    )
                    if result.returncode == 0:
                        networks.extend(self._parse_linux_ip_addr(result.stdout))
                except FileNotFoundError:
                    # Fallback to ifconfig
                    result = subprocess.run(
                        ["ifconfig"], capture_output=True, text=True, check=False
                    )
                    if result.returncode == 0:
                        networks.extend(self._parse_ifconfig(result.stdout))
        except Exception as e:
            print(f"Warning: Could not detect network interfaces: {e}")

        return list(set(networks))  # Remove duplicates

    def _detect_windows_network(self) -> str:
        """Enhanced Windows network detection."""
        try:
            # Try ipconfig with more detailed parsing
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                networks = self._parse_windows_ipconfig(result.stdout)
                if networks:
                    return networks[0]

            # Try route print as fallback
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    if "0.0.0.0" in line and "Gateway" not in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            gateway = parts[2]
                            if self._is_valid_ip(gateway):
                                network = ".".join(gateway.split(".")[:-1]) + ".0/24"
                                return network
        except Exception as e:
            print(f"Windows network detection error: {e}")

        return "192.168.1.0/24"

    def _parse_windows_ipconfig(self, output: str) -> List[str]:
        """Parse Windows ipconfig output to extract network ranges."""
        networks = []
        lines = output.split("\n")
        current_adapter = ""
        ip_address = ""
        subnet_mask = ""

        for line in lines:
            line = line.strip()

            if "adapter" in line.lower() and ":" in line:
                current_adapter = line
                ip_address = ""
                subnet_mask = ""
            elif "IPv4 Address" in line or "IP Address" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ip_address = parts[1].strip().split("(")[0].strip()
            elif "Subnet Mask" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    subnet_mask = parts[1].strip()

                # When we have both IP and subnet mask, calculate network
                if ip_address and subnet_mask and self._is_valid_ip(ip_address):
                    try:
                        if not ip_address.startswith(
                            "127."
                        ) and not ip_address.startswith("169.254."):
                            # Convert subnet mask to CIDR
                            cidr = self._subnet_mask_to_cidr(subnet_mask)
                            if cidr:
                                network = ipaddress.IPv4Network(
                                    f"{ip_address}/{cidr}", strict=False
                                )
                                networks.append(str(network))
                    except Exception:
                        pass

        return networks

    def _parse_linux_ip_addr(self, output: str) -> List[str]:
        """Parse Linux 'ip addr' output to extract network ranges."""
        networks = []

        for line in output.split("\n"):
            line = line.strip()
            if (
                "inet " in line
                and not line.startswith("inet 127.")
                and not line.startswith("inet 169.254.")
            ):
                parts = line.split()
                for part in parts:
                    if "/" in part and self._is_valid_ip(part.split("/")[0]):
                        try:
                            network = ipaddress.IPv4Network(part, strict=False)
                            networks.append(str(network))
                        except Exception:
                            pass

        return networks

    def _parse_ifconfig(self, output: str) -> List[str]:
        """Parse ifconfig output to extract network ranges."""
        networks = []

        lines = output.split("\n")
        for i, line in enumerate(lines):
            if "inet " in line and "inet addr:" in line:
                # Extract IP address
                ip_match = re.search(r"inet addr:(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        # Look for netmask in the same line or next lines
                        netmask_match = re.search(r"Mask:(\d+\.\d+\.\d+\.\d+)", line)
                        if netmask_match:
                            try:
                                cidr = self._subnet_mask_to_cidr(netmask_match.group(1))
                                if cidr:
                                    network = ipaddress.IPv4Network(
                                        f"{ip}/{cidr}", strict=False
                                    )
                                    networks.append(str(network))
                            except Exception:
                                pass

        return networks

    def _subnet_mask_to_cidr(self, subnet_mask: str) -> Optional[int]:
        """Convert subnet mask to CIDR notation."""
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}").prefixlen
        except Exception:
            return None

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except Exception:
            return False

    def _ping_host(self, ip: str) -> bool:
        """
        Ping a single host to check if it's reachable.

        Uses platform-specific ping commands:
        - Windows: ping -n 1 -w <timeout_ms> <ip>
        - Linux/macOS: ping -c 1 -W <timeout_sec> <ip>

        Args:
            ip: IP address to ping

        Returns:
            bool: True if host responds to ping, False otherwise
        """
        try:
            if platform.system() == "Windows":
                # Windows ping: -n count, -w timeout in milliseconds
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            else:
                # Linux/macOS ping: -c count, -W timeout in seconds
                cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]

            # Run ping command and check return code
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return result.returncode == 0
        except (subprocess.CalledProcessError, OSError, FileNotFoundError):
            # If ping command fails for any reason, assume host is unreachable
            return False

    def _get_mac_address(self, ip: str) -> Optional[str]:
        """
        Retrieve MAC address for an IP using the system ARP table.

        The ARP (Address Resolution Protocol) table maintains a mapping
        of IP addresses to MAC addresses for recently contacted hosts.

        Args:
            ip: IP address to lookup

        Returns:
            Optional[str]: MAC address in uppercase format (XX:XX:XX:XX:XX:XX)
                          or None if not found
        """
        try:
            if platform.system() == "Windows":
                # Windows ARP command: arp -a <ip>
                result = subprocess.run(
                    ["arp", "-a", ip], capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        # Look for lines containing the IP and 'dynamic' entries
                        if ip in line and "dynamic" in line.lower():
                            parts = line.split()
                            for part in parts:
                                # Windows uses dash format: AA-BB-CC-DD-EE-FF
                                if "-" in part and len(part) == 17:
                                    return part.replace("-", ":").upper()
            else:
                # Linux/macOS ARP command: arp -n <ip>
                result = subprocess.run(
                    ["arp", "-n", ip], capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]  # MAC is typically 3rd column
                                # Unix systems use colon format: AA:BB:CC:DD:EE:FF
                                if ":" in mac and len(mac) == 17:
                                    return mac.upper()
        except (subprocess.CalledProcessError, OSError, FileNotFoundError, IndexError):
            # ARP lookup can fail if host hasn't been contacted recently
            pass
        return None

    def _get_hostname(self, ip: str) -> Optional[str]:
        """
        Attempt to resolve hostname from IP address using reverse DNS lookup.

        Args:
            ip: IP address to resolve

        Returns:
            Optional[str]: Hostname if resolution succeeds, None otherwise
        """
        try:
            # Perform reverse DNS lookup
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            # DNS resolution can fail for various reasons:
            # - No PTR record exists
            # - DNS server timeout
            # - Host doesn't support reverse DNS
            return None

    def _scan_ports(self, ip: str, ports: Optional[List[int]] = None) -> List[int]:
        """
        Scan common ports on a target host to identify running services.

        This function attempts TCP connections to determine which ports
        are open and accepting connections.

        Args:
            ip: Target IP address to scan
            ports: List of ports to scan. If None, uses common service ports.

        Returns:
            List[int]: List of open port numbers
        """
        if ports is None:
            # Common ports for various services
            ports = [
                22,  # SSH
                23,  # Telnet
                53,  # DNS
                80,  # HTTP
                135,  # RPC Endpoint Mapper
                139,  # NetBIOS Session Service
                443,  # HTTPS
                445,  # SMB
                993,  # IMAPS
                995,  # POP3S
                1723,  # PPTP
                3389,  # Remote Desktop Protocol (RDP)
                5900,  # VNC
                8080,  # HTTP Alternate
            ]

        open_ports = []
        for port in ports:
            try:
                # Create TCP socket and attempt connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Quick timeout for port scanning
                result = sock.connect_ex((ip, port))
                if result == 0:  # Connection successful
                    open_ports.append(port)
                sock.close()
            except (socket.error, OSError):
                # Connection failed - port is closed or filtered
                pass
        return open_ports

    def _get_mac_vendor(self, mac: str) -> str:
        """
        Lookup the vendor/manufacturer for a MAC address using online API.

        Uses the first 6 characters (OUI - Organizationally Unique Identifier)
        of the MAC address to identify the manufacturer. Results are cached
        to avoid repeated API calls for the same vendor.

        Args:
            mac: MAC address in format XX:XX:XX:XX:XX:XX

        Returns:
            str: Vendor name or "Unknown" if lookup fails
        """
        if not requests or not mac:
            return "Unknown"

        # Extract OUI (first 6 hex characters) for caching
        oui = mac.replace(":", "").upper()[:6]
        if oui in self.mac_vendors:
            return self.mac_vendors[oui]  # Return cached result

        try:
            # Query macvendors.com API (free, no registration required)
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.status_code == 200:
                vendor = response.text.strip()
                self.mac_vendors[oui] = vendor  # Cache the result
                return vendor
        except (requests.RequestException, requests.Timeout):
            # API call failed - network issues, rate limiting, etc.
            pass

        # Cache "Unknown" to avoid repeated failed lookups
        self.mac_vendors[oui] = "Unknown"
        return "Unknown"

    def _identify_device_type(self, device_info: Dict) -> str:
        """
        Identify device type based on various indicators including
        enrichment data from mDNS, SSDP/UPnP, NetBIOS, and HTTP probes.

        Args:
            device_info: Dictionary containing device information

        Returns:
            str: Device type classification
        """
        hostname = (device_info.get("hostname") or "").lower()
        vendor = (device_info.get("vendor") or "").lower()
        open_ports = device_info.get("open_ports", [])
        mac = device_info.get("mac", "")

        # Enrichment-derived fields (may be absent if --enrich not used)
        friendly = (device_info.get("friendly_name") or "").lower()
        model = (device_info.get("model") or "").lower()
        manufacturer = (device_info.get("manufacturer") or "").lower()
        mdns_types = {
            s.get("type", "").lower() for s in device_info.get("mdns_services", [])
        }
        upnp_type = (
            device_info.get("upnp_info", {}).get("upnp_device_type") or ""
        ).lower()
        http_title = (device_info.get("http_title") or "").lower()

        # Combine all text signals for keyword matching
        all_text = " ".join(
            [hostname, friendly, model, manufacturer, vendor, upnp_type, http_title]
        )

        # ---- Router / Gateway ----
        if any(kw in all_text for kw in ["router", "gateway", "access point"]):
            return "Router/Gateway"
        if "internetgatewaydevice" in upnp_type:
            return "Router/Gateway"
        if any(port in open_ports for port in [80, 443, 22, 23]):
            if any(
                v in vendor
                for v in [
                    "cisco",
                    "netgear",
                    "linksys",
                    "tp-link",
                    "asus",
                    "ubiquiti",
                    "arris",
                    "eero",
                    "huawei",
                ]
            ):
                return "Router/Gateway"

        # ---- Smart TV / Media Device ----
        if (
            "googlecast" in mdns_types
            or "airplay" in mdns_types
            or "raop" in mdns_types
        ):
            if any(
                kw in all_text
                for kw in ["tv", "chromecast", "roku", "firestick", "apple tv"]
            ):
                return "Smart TV"
            return "Media Device (Streaming)"
        if "mediarenderer" in upnp_type or "mediaserver" in upnp_type:
            return "Smart TV/Media Device"
        if any(
            kw in all_text
            for kw in ["tv", "roku", "chromecast", "firestick", "apple-tv"]
        ):
            return "Smart TV/Media Device"
        if any(v in vendor for v in ["samsung", "lg", "sony", "roku", "amazon"]):
            if 8080 in open_ports or 1900 in open_ports:
                return "Smart TV/Media Device"

        # ---- Printer ----
        if "ipp" in mdns_types or "printer" in mdns_types:
            return "Printer"
        if any(
            kw in all_text
            for kw in [
                "printer",
                "hp-",
                "canon",
                "epson",
                "brother",
                "laserjet",
                "officejet",
                "deskjet",
            ]
        ):
            return "Printer"
        if 631 in open_ports or 9100 in open_ports:
            return "Printer"

        # ---- Mobile Device ----
        if any(
            kw in all_text for kw in ["iphone", "ipad", "android", "pixel", "galaxy"]
        ):
            return "Mobile Device"
        if "companion-link" in mdns_types:
            return "Mobile Device (Apple)"
        if "apple" in vendor and mac.startswith(("28:CF:E9", "3C:15:C2", "48:60:BC")):
            return "Mobile Device (iPhone/iPad)"

        # ---- Computer ----
        if "workstation" in mdns_types or "rdp" in mdns_types:
            return "Computer"
        if device_info.get("netbios_name"):
            if 3389 in open_ports:
                return "Windows Computer"
            return "Computer"
        if any(
            kw in all_text
            for kw in ["desktop", "laptop", "pc", "macbook", "imac", "thinkpad"]
        ):
            return "Computer"
        if 3389 in open_ports:
            return "Windows Computer"
        if 22 in open_ports and "apple" in vendor:
            return "Mac Computer"

        # ---- Smart Speaker / Voice Assistant ----
        if any(
            kw in all_text
            for kw in [
                "echo",
                "alexa",
                "google home",
                "homepod",
                "nest mini",
                "nest hub",
                "nest audio",
            ]
        ):
            return "Smart Speaker"
        if "spotify-connect" in mdns_types and "googlecast" in mdns_types:
            return "Smart Speaker"

        # ---- HomeKit / IoT ----
        if "homekit" in mdns_types or "hap" in mdns_types:
            return "HomeKit Device"
        if any(
            kw in all_text
            for kw in ["nest", "hue", "ring", "wemo", "smartthings", "tuya"]
        ):
            return "IoT Device"

        # ---- Network Storage (NAS) ----
        if "smb" in mdns_types or "afpovertcp" in mdns_types:
            return "Network Storage (NAS)"
        if any(port in open_ports for port in [445, 139, 548, 2049]):
            return "Network Storage (NAS)"

        # ---- Gaming Console ----
        if any(
            kw in all_text
            for kw in ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch"]
        ):
            return "Gaming Console"

        # ---- Fallbacks ----
        if len(open_ports) == 0 and vendor != "Unknown":
            return "IoT Device (likely)"
        if open_ports:
            return "Network Device"
        return "Unknown Device"

    def _identify_services(self, ip: str, open_ports: List[int]) -> Dict[int, str]:
        """
        Identify services running on open ports.

        Args:
            ip: Target IP address
            open_ports: List of open port numbers

        Returns:
            Dict mapping port numbers to service descriptions
        """
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC Endpoint Mapper",
            139: "NetBIOS Session",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB/CIFS",
            548: "AFP (Apple Filing Protocol)",
            631: "IPP (Internet Printing Protocol)",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP VPN",
            2049: "NFS",
            3389: "RDP (Remote Desktop)",
            5900: "VNC",
            8080: "HTTP Alternate",
            9100: "Raw Printing",
        }

        services = {}
        for port in open_ports:
            if port in service_map:
                services[port] = service_map[port]
            else:
                # Try banner grabbing for unknown ports
                banner = self._grab_banner(ip, port)
                if banner:
                    services[port] = f"Unknown ({banner[:30]}...)"
                else:
                    services[port] = "Unknown Service"

        return services

    def _grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """
        Attempt to grab service banner from a port.

        Args:
            ip: Target IP address
            port: Target port
            timeout: Connection timeout

        Returns:
            Optional[str]: Service banner if available
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Send basic HTTP request for web servers
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

            # Receive banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            # Clean up banner
            if banner:
                return banner.split("\n")[0][:50]

        except (socket.error, socket.timeout, UnicodeDecodeError):
            pass

        return None

    # ========================================================================
    # Enrichment Methods – mDNS, SSDP/UPnP, NetBIOS, HTTP, TLS
    # ========================================================================

    def _mdns_discover_services(self, timeout: float = 5.0) -> Dict[str, List[Dict]]:
        """
        Discover mDNS/Bonjour services advertised on the local network.

        Returns:
            Dict mapping IP addresses to lists of discovered service dicts.
        """
        if not HAS_ZEROCONF:
            if self.verbose:
                print(
                    "zeroconf package not installed; skipping mDNS discovery. "
                    "Install with: pip install zeroconf"
                )
            return {}

        SERVICE_TYPES = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_ipp._tcp.local.",
            "_printer._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_googlecast._tcp.local.",
            "_smb._tcp.local.",
            "_afpovertcp._tcp.local.",
            "_ssh._tcp.local.",
            "_rfb._tcp.local.",
            "_homekit._tcp.local.",
            "_hap._tcp.local.",
            "_companion-link._tcp.local.",
            "_workstation._tcp.local.",
            "_device-info._tcp.local.",
            "_rdp._tcp.local.",
            "_spotify-connect._tcp.local.",
        ]

        results: Dict[str, List[Dict]] = {}
        discovered: List[tuple] = []

        class _Listener:
            """Collects service names as they are found."""

            def add_service(self, zc, type_, name):
                discovered.append((type_, name))

            def remove_service(self, zc, type_, name):
                pass

            def update_service(self, zc, type_, name):
                pass

        try:
            zc = Zeroconf(ip_version=IPVersion.V4Only)  # type: ignore[possibly-undefined]
            listener = _Listener()
            browsers = []
            for stype in SERVICE_TYPES:
                try:
                    browsers.append(ServiceBrowser(zc, stype, listener))  # type: ignore[arg-type,possibly-undefined]
                except (OSError, ValueError):
                    pass

            # Let the browsers collect responses
            time.sleep(timeout)

            # Resolve each discovered service
            for type_, name in discovered:
                try:
                    info = zc.get_service_info(type_, name, timeout=2000)
                    if info and info.parsed_addresses():
                        for addr in info.parsed_addresses(IPVersion.V4Only):  # type: ignore[possibly-undefined]
                            if addr not in results:
                                results[addr] = []
                            entry: Dict[str, Any] = {
                                "type": type_.replace("._tcp.local.", "")
                                .replace("._udp.local.", "")
                                .lstrip("_"),
                                "name": name.replace(f".{type_}", ""),
                                "port": info.port,
                                "server": info.server,
                            }
                            if info.properties:
                                props = {}
                                for k, v in info.properties.items():
                                    pk = (
                                        k.decode("utf-8", errors="ignore")
                                        if isinstance(k, bytes)
                                        else str(k)
                                    )
                                    pv = (
                                        v.decode("utf-8", errors="ignore")
                                        if isinstance(v, bytes)
                                        else str(v)
                                    )
                                    props[pk] = pv
                                entry["properties"] = props
                                # Promote common useful keys
                                if "md" in props:
                                    entry["model"] = props["md"]
                                if "fn" in props:
                                    entry["friendly_name"] = props["fn"]
                                if "am" in props:
                                    entry["model_name"] = props["am"]
                            results[addr].append(entry)
                except (OSError, ValueError):
                    pass

            zc.close()

        except (OSError, RuntimeError) as e:
            if self.verbose:
                print(f"mDNS discovery error: {e}")

        return results

    def _ssdp_discover(self, timeout: float = 3.0) -> Dict[str, Dict]:
        """
        Discover UPnP devices on the network via SSDP M-SEARCH.

        Returns:
            Dict mapping IP addresses to UPnP device information.
        """
        results: Dict[str, Dict] = {}

        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900
        message = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            f"MX: {int(timeout)}\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout + 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.sendto(message.encode(), (SSDP_ADDR, SSDP_PORT))

            end_time = time.time() + timeout + 1
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    response = data.decode("utf-8", errors="ignore")

                    headers: Dict[str, str] = {}
                    for line in response.split("\r\n"):
                        if ":" in line:
                            key, _, value = line.partition(":")
                            headers[key.strip().upper()] = value.strip()

                    if ip not in results:
                        results[ip] = {
                            "ssdp_server": headers.get("SERVER", ""),
                            "ssdp_location": headers.get("LOCATION", ""),
                            "ssdp_usn": headers.get("USN", ""),
                        }

                    # Fetch full UPnP device description from LOCATION URL
                    location = headers.get("LOCATION", "")
                    if location and "upnp_friendly_name" not in results.get(ip, {}):
                        self._fetch_upnp_description(ip, location, results)

                except socket.timeout:
                    break
                except (socket.error, UnicodeDecodeError):
                    continue

            sock.close()
        except (socket.error, OSError) as e:
            if self.verbose:
                print(f"SSDP discovery error: {e}")

        return results

    def _fetch_upnp_description(self, ip: str, location: str, results: Dict):
        """Fetch and parse UPnP device description XML from the LOCATION URL."""
        if not requests:
            return
        try:
            resp = requests.get(location, timeout=3)
            if resp.status_code != 200:
                return
            root = ET.fromstring(resp.text)
            ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}
            device_el = root.find(".//upnp:device", ns)
            if device_el is None:
                return
            fields = {
                "upnp_friendly_name": "upnp:friendlyName",
                "upnp_manufacturer": "upnp:manufacturer",
                "upnp_model": "upnp:modelName",
                "upnp_model_number": "upnp:modelNumber",
                "upnp_serial": "upnp:serialNumber",
                "upnp_device_type": "upnp:deviceType",
                "upnp_presentation_url": "upnp:presentationURL",
            }
            for key, xpath in fields.items():
                val = device_el.findtext(xpath, "", ns).strip()
                if val:
                    results[ip][key] = val
        except (requests.RequestException, ET.ParseError):
            pass

    def _get_netbios_name(self, ip: str, timeout: float = 2.0) -> Optional[str]:
        """
        Resolve the NetBIOS (workstation) name for a host.

        Tries the OS utility first (nbtstat / nmblookup), then falls back
        to a raw NBNS NBSTAT query on UDP 137.
        """
        # Method 1: OS utility
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["nbtstat", "-A", ip],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1,
                    check=False,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        line = line.strip()
                        if "<00>" in line and "UNIQUE" in line:
                            name = line.split("<00>")[0].strip()
                            if name and not name.startswith("__"):
                                return name
            else:
                result = subprocess.run(
                    ["nmblookup", "-A", ip],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1,
                    check=False,
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "<00>" in line:
                            name = line.strip().split("<00>")[0].strip()
                            if name:
                                return name
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Method 2: Raw NBNS NBSTAT query
        try:
            query = (
                b"\xa9\x0c"  # Transaction ID
                b"\x00\x00"  # Flags
                b"\x00\x01"  # Questions: 1
                b"\x00\x00\x00\x00\x00\x00"  # Answers/Auth/Additional: 0
                b"\x20"  # Encoded-name length (32)
                b"\x43\x4b"  # Encoded '*'
            )
            query += b"\x43\x41" * 15  # Encoded padding spaces
            query += b"\x00"  # Name terminator
            query += b"\x00\x21"  # Type: NBSTAT
            query += b"\x00\x01"  # Class: IN

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (ip, 137))
            data, _ = sock.recvfrom(1024)
            sock.close()

            # Response may use name-pointer compression or a full name
            for num_names_offset in [24, 56]:
                if len(data) <= num_names_offset + 18:
                    continue
                num_names = data[num_names_offset]
                if not (0 < num_names < 30):
                    continue
                name_offset = num_names_offset + 1
                for i in range(min(num_names, 10)):
                    entry = name_offset + i * 18
                    if len(data) <= entry + 18:
                        break
                    try:
                        name = data[entry : entry + 15].decode("ascii").strip()
                        suffix = data[entry + 15]
                        flags = struct.unpack(">H", data[entry + 16 : entry + 18])[0]
                        # suffix 0x00 + unique flag → workstation name
                        if name and suffix == 0x00 and (flags & 0x8000) == 0:
                            if all(c.isprintable() for c in name):
                                return name
                    except (UnicodeDecodeError, struct.error):
                        continue
        except (socket.error, socket.timeout, OSError):
            pass

        return None

    def _get_http_info(self, ip: str, port: int = 80) -> Dict[str, str]:
        """
        Probe an HTTP(S) port for server header, page title, and X-Powered-By.
        """
        info: Dict[str, str] = {}
        if not requests:
            return info

        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        scheme = "https" if port in (443, 8443) else "http"
        try:
            resp = requests.get(
                f"{scheme}://{ip}:{port}/",
                timeout=3,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "NetworkScanner/1.0"},
            )
            server = resp.headers.get("Server", "")
            if server:
                info["http_server"] = server
            powered = resp.headers.get("X-Powered-By", "")
            if powered:
                info["http_powered_by"] = powered
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>",
                resp.text[:4096],
                re.IGNORECASE | re.DOTALL,
            )
            if title_match:
                info["http_title"] = title_match.group(1).strip()[:100]
        except (requests.RequestException, OSError):
            pass
        return info

    def _get_tls_cert_info(self, ip: str, port: int = 443) -> Dict[str, str]:
        """
        Retrieve TLS certificate metadata (subject CN, issuer, SANs, expiry).
        """
        info: Dict[str, str] = {}
        try:
            # Try validated connection first (gives parsed cert dict)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((ip, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        self._extract_cert_fields(cert, info)
                    info["tls_version"] = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        info["tls_cipher"] = cipher[0]
        except ssl.SSLCertVerificationError:
            # Self-signed / untrusted – reconnect without verification
            try:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=3) as raw:
                    with ctx2.wrap_socket(raw, server_hostname=ip) as ssock:
                        info["tls_version"] = ssock.version() or ""
                        cipher = ssock.cipher()
                        if cipher:
                            info["tls_cipher"] = cipher[0]
                        info["tls_self_signed"] = "true"
            except (socket.error, ssl.SSLError, OSError):
                pass
        except (socket.error, ssl.SSLError, OSError, ConnectionRefusedError):
            pass
        return info

    @staticmethod
    def _extract_cert_fields(cert: Dict, info: Dict):
        """Pull subject CN, issuer, SANs, and expiry from a parsed cert dict."""
        for rdn in cert.get("subject", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    info["tls_subject_cn"] = attr_value
        for rdn in cert.get("issuer", ()):
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    info["tls_issuer"] = attr_value
        sans = cert.get("subjectAltName", ())
        dns_names = [v for t, v in sans if t == "DNS"]
        if dns_names:
            info["tls_san_dns"] = dns_names[:5]
        not_after = cert.get("notAfter", "")
        if not_after:
            info["tls_not_after"] = not_after

    def _load_device_history(self) -> Dict:
        """Load device history from file."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_device_history(self, history: Dict):
        """Save device history to file."""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except OSError as e:
            print(f"Warning: Could not save device history: {e}")

    def _track_device_changes(self, current_devices: Dict[str, Dict]) -> Dict:
        """
        Track changes in devices compared to previous scans.

        Args:
            current_devices: Currently discovered devices

        Returns:
            Dict: Summary of changes (new, missing, changed devices)
        """
        history = self._load_device_history()
        last_scan = history.get("last_scan", {})
        changes = {
            "new_devices": [],
            "missing_devices": [],
            "changed_devices": [],
            "timestamp": datetime.now().isoformat(),
        }

        # Find new devices
        for ip, device in current_devices.items():
            if ip not in last_scan:
                changes["new_devices"].append(
                    {
                        "ip": ip,
                        "hostname": device.get("hostname"),
                        "mac": device.get("mac"),
                        "vendor": device.get("vendor"),
                        "device_type": device.get("device_type"),
                    }
                )

        # Find missing devices (seen in last scan but not current)
        for ip, device in last_scan.items():
            if ip not in current_devices:
                # Only report as missing if last seen recently (within 24 hours)
                last_seen = datetime.fromisoformat(device.get("last_seen", ""))
                if datetime.now() - last_seen < timedelta(hours=24):
                    changes["missing_devices"].append(
                        {
                            "ip": ip,
                            "hostname": device.get("hostname"),
                            "mac": device.get("mac"),
                            "last_seen": device.get("last_seen"),
                        }
                    )

        # Find changed devices (same IP, different MAC - potential security issue)
        for ip, device in current_devices.items():
            if ip in last_scan:
                old_mac = last_scan[ip].get("mac")
                new_mac = device.get("mac")
                if old_mac and new_mac and old_mac != new_mac:
                    changes["changed_devices"].append(
                        {
                            "ip": ip,
                            "old_mac": old_mac,
                            "new_mac": new_mac,
                            "hostname": device.get("hostname"),
                        }
                    )

        # Update history
        history["last_scan"] = current_devices
        history["scan_history"] = history.get("scan_history", [])
        history["scan_history"].append(
            {
                "timestamp": changes["timestamp"],
                "device_count": len(current_devices),
                "changes": changes,
            }
        )

        # Keep only last 30 scan records
        history["scan_history"] = history["scan_history"][-30:]

        self._save_device_history(history)
        return changes

    def _measure_ping_time(self, ip: str) -> Optional[float]:
        """
        Measure ping response time more accurately.

        Args:
            ip: IP address to ping

        Returns:
            Optional[float]: Ping time in milliseconds, None if failed
        """
        try:
            start_time = time.time()
            if platform.system() == "Windows":
                cmd = ["ping", "-n", "1", "-w", "2000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "2", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            end_time = time.time()

            if result.returncode == 0:
                # Try to extract actual ping time from output
                output = result.stdout
                if platform.system() == "Windows":
                    # Look for "time<1ms" or "time=32ms" pattern
                    match = re.search(r"time[<=](\d+)ms", output)
                    if match:
                        return float(match.group(1))
                else:
                    # Look for "time=0.123 ms" pattern
                    match = re.search(r"time=([0-9.]+) ms", output)
                    if match:
                        return float(match.group(1))

                # Fallback to measured time
                return (end_time - start_time) * 1000

        except (subprocess.CalledProcessError, OSError, ValueError):
            pass

        return None

    def _scan_single_host(self, ip: str, scan_ports: bool = False) -> Optional[Dict]:
        """
        Perform comprehensive scan of a single host.

        This is the main scanning function that combines multiple techniques
        to gather information about a single network host.

        Args:
            ip: IP address to scan
            scan_ports: Whether to perform port scanning (slower but more informative)

        Returns:
            Optional[Dict]: Device information dictionary if host is reachable,
                           None if host doesn't respond to ping
        """
        # First check if host is alive
        if not self._ping_host(ip):
            return None

        # Measure ping response time
        response_time = self._measure_ping_time(ip)

        # Initialize device information structure
        device_info = {
            "ip": ip,
            "hostname": self._get_hostname(ip),
            "mac": self._get_mac_address(ip),
            "vendor": None,
            "open_ports": [],
            "services": {},
            "device_type": "Unknown",
            "last_seen": datetime.now().isoformat(),
            "response_time": response_time,
        }

        # Get vendor information if MAC address was found
        if device_info["mac"]:
            device_info["vendor"] = self._get_mac_vendor(device_info["mac"])

        # Perform port scan if requested
        if scan_ports:
            device_info["open_ports"] = self._scan_ports(ip)
            device_info["services"] = self._identify_services(
                ip, device_info["open_ports"]
            )

        # Identify device type
        device_info["device_type"] = self._identify_device_type(device_info)

        return device_info

    def _scan_candidate_hosts(
        self, ips: List[str], scan_method: str
    ) -> List[Dict[str, Any]]:
        """Scan a small set of candidate IPs in parallel."""
        devices = []
        if not ips:
            return devices

        with ThreadPoolExecutor(
            max_workers=min(self.max_threads, len(ips))
        ) as executor:
            future_to_ip = {
                executor.submit(self._scan_single_host, ip): ip for ip in ips
            }

            for future in as_completed(future_to_ip):
                try:
                    device_info = future.result(timeout=30)
                    if device_info:
                        device_info["scan_method"] = scan_method
                        devices.append(device_info)
                except Exception:
                    pass

        return devices

    def scan_network(self, custom_range: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Comprehensive network scanning with enhanced mesh network support.

        Performs a complete scan of the specified network range using multiple methods:
        1. ICMP ping scanning (traditional)
        2. ARP table scanning (for mesh networks)
        3. Aggressive scanning (for isolated networks)

        Args:
            custom_range: Optional custom network range in CIDR notation.
                        If not provided, uses the instance network range.

        Returns:
            List[Dict[str, Any]]: List of discovered devices with their information.
        """
        # Determine network range to scan
        if custom_range:
            self.network_range = custom_range
        elif not hasattr(self, "network_range") or not self.network_range:
            self.network_range = self._get_network_range()

        network_range = self.network_range
        print(f"Scanning network range: {network_range}")

        # Get list of hosts to scan
        hosts = self._get_hosts_to_scan(network_range)
        print(f"Scanning {len(hosts)} potential hosts...")

        # Initialize results list
        all_devices = []

        # Method 1: Traditional ping scanning
        print("Starting ICMP ping scan...")
        ping_devices = self._ping_scan_hosts(hosts)
        all_devices.extend(ping_devices)
        print(f"Ping scan found {len(ping_devices)} devices")

        # Method 2: ARP table scanning (especially useful for mesh networks)
        if self.args.arp_scan:
            print("Starting ARP table scan...")
            arp_devices = self._arp_scan_network()
            # Merge ARP results with ping results
            all_devices = self._merge_device_lists(all_devices, arp_devices)
            print(f"ARP scan found {len(arp_devices)} additional devices")

        # Method 3: Aggressive scanning for isolated networks
        if self.args.aggressive:
            print("Starting aggressive scan...")
            aggressive_devices = self._aggressive_scan_network(network_range)
            all_devices = self._merge_device_lists(all_devices, aggressive_devices)
            print(f"Aggressive scan found {len(aggressive_devices)} additional devices")

        # Remove duplicates and enhance device information
        unique_devices = self._deduplicate_devices(all_devices)

        # Network-wide enrichment: mDNS and SSDP (run once, not per-host)
        if getattr(self.args, "enrich", False):
            print("Running mDNS/Bonjour and SSDP/UPnP discovery...")
            with ThreadPoolExecutor(max_workers=2) as executor:
                mdns_future = executor.submit(self._mdns_discover_services)
                ssdp_future = executor.submit(self._ssdp_discover)

                try:
                    self.mdns_services = mdns_future.result(timeout=15)
                except Exception as e:
                    self.mdns_services = {}
                    if self.verbose:
                        print(f"mDNS discovery failed: {e}")

                try:
                    self.ssdp_devices = ssdp_future.result(timeout=10)
                except Exception as e:
                    self.ssdp_devices = {}
                    if self.verbose:
                        print(f"SSDP discovery failed: {e}")

            if self.mdns_services:
                print(f"mDNS found services on {len(self.mdns_services)} device(s)")
            if self.ssdp_devices:
                print(f"SSDP found {len(self.ssdp_devices)} device(s)")

        # Enhance device information for all discovered devices
        print("Enhancing device information...")
        enhanced_devices = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_device = {
                executor.submit(self._enhance_device_info, device): device
                for device in unique_devices
            }

            for future in as_completed(future_to_device):
                try:
                    enhanced_device = future.result(timeout=30)
                    if enhanced_device:
                        enhanced_devices.append(enhanced_device)
                except Exception as e:
                    print(f"Error enhancing device info: {e}")

        # Track changes if enabled
        if (
            hasattr(self.args, "track_changes")
            and self.args.track_changes
            and hasattr(self, "last_scan_file")
            and self.last_scan_file
        ):
            enhanced_devices = self._track_changes(enhanced_devices)

        # Store results in instance variable for backward compatibility
        self.devices = {device["ip"]: device for device in enhanced_devices}

        print(f"Scan completed. Found {len(enhanced_devices)} devices total.")
        return enhanced_devices

    def _get_hosts_to_scan(self, network_range: str) -> List[str]:
        """Generate list of host IPs to scan from network range."""
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            print(f"Error parsing network range: {e}")
            return []

    def _ping_scan_hosts(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Perform traditional ping-based scanning."""
        devices = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_host = {
                executor.submit(self._scan_single_host, host): host for host in hosts
            }

            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    device_info = future.result(timeout=30)
                    if device_info:
                        devices.append(device_info)
                        print(
                            f"Found device: {device_info['ip']} - {device_info.get('hostname', 'Unknown')}"
                        )
                except Exception as e:
                    if self.verbose:
                        print(f"Error scanning {host}: {e}")

        return devices

    def _arp_scan_network(self) -> List[Dict[str, Any]]:
        """
        Scan the ARP table to find devices that may not respond to ping.
        Particularly useful for mesh networks where devices may be isolated.
        """
        devices = []

        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, check=False
                )
            else:
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, check=False
                )

            if result.returncode == 0:
                devices = self._parse_arp_output(result.stdout)
                print(f"ARP table contains {len(devices)} entries")
            else:
                print("Could not access ARP table")

        except Exception as e:
            print(f"Error scanning ARP table: {e}")

        return devices

    def _parse_arp_output(self, arp_output: str) -> List[Dict[str, Any]]:
        """Parse ARP command output to extract device information."""
        devices = []

        for line in arp_output.split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                if platform.system() == "Windows":
                    # Windows ARP format: "192.168.1.1     00-11-22-33-44-55     dynamic"
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line
                    )
                    if match:
                        ip, mac, arp_type = match.groups()
                        if arp_type.lower() == "dynamic" and self._is_in_network_range(
                            ip
                        ):
                            devices.append(
                                {
                                    "ip": ip,
                                    "mac": mac.replace("-", ":").lower(),
                                    "hostname": "Unknown",
                                    "scan_method": "ARP",
                                    "ping_time": 0,
                                    "last_seen": datetime.now().isoformat(),
                                }
                            )
                else:
                    # Linux/macOS ARP format: "192.168.1.1 (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})", line
                    )
                    if match:
                        ip, mac = match.groups()
                        if self._is_in_network_range(ip):
                            devices.append(
                                {
                                    "ip": ip,
                                    "mac": mac.lower(),
                                    "hostname": "Unknown",
                                    "scan_method": "ARP",
                                    "ping_time": 0,
                                    "last_seen": datetime.now().isoformat(),
                                }
                            )

            except Exception as e:
                if self.verbose:
                    print(f"Error parsing ARP line '{line}': {e}")

        return devices

    def _aggressive_scan_network(self, network_range: str) -> List[Dict[str, Any]]:
        """
        Perform aggressive scanning for mesh networks.
        Uses additional techniques to discover isolated devices.
        """
        devices = []

        print("Performing broadcast ping...")
        # Method 1: Broadcast ping
        try:
            network = ipaddress.IPv4Network(network_range)
            broadcast_ip = str(network.broadcast_address)

            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ping", "-n", "3", broadcast_ip],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "3", "-b", broadcast_ip],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            if result.returncode == 0:
                print("Broadcast ping sent, checking ARP table...")
                # Wait a moment for ARP table to update
                time.sleep(2)
                arp_devices = self._arp_scan_network()
                devices.extend(arp_devices)

        except Exception as e:
            print(f"Broadcast ping failed: {e}")

        # Method 2: Common device IP scanning
        print("Scanning common device IPs...")
        common_ips = self._get_common_device_ips(network_range)
        devices.extend(self._scan_candidate_hosts(common_ips, "Aggressive"))

        # Method 3: Router/Gateway intensive scan
        print("Performing router discovery...")
        gateway_devices = self._scan_gateway_neighbors(network_range)
        devices.extend(gateway_devices)

        return devices

    def _get_common_device_ips(self, network_range: str) -> List[str]:
        """Get list of commonly used IP addresses in the network."""
        try:
            network = ipaddress.IPv4Network(network_range)
            base = str(network.network_address)
            base_parts = base.split(".")
            base_ip = ".".join(base_parts[:3])

            # Common IPs that devices often use
            common_suffixes = [1, 2, 3, 4, 5, 10, 20, 50, 100, 150, 200, 254]
            return [
                f"{base_ip}.{suffix}"
                for suffix in common_suffixes
                if ipaddress.IPv4Address(f"{base_ip}.{suffix}") in network
            ]
        except Exception:
            return []

    def _scan_gateway_neighbors(self, network_range: str) -> List[Dict[str, Any]]:
        """Scan IP addresses near the gateway for additional devices."""
        devices = []

        try:
            network = ipaddress.IPv4Network(network_range)
            # Assume gateway is usually .1
            gateway_ip = str(network.network_address + 1)

            # Test if this is actually the gateway
            if self._ping_host(gateway_ip):
                print(f"Found gateway at {gateway_ip}, scanning nearby IPs...")

                # Scan IPs around the gateway (common in mesh networks)
                gateway_parts = gateway_ip.split(".")
                base_ip = ".".join(gateway_parts[:3])
                candidate_ips = []

                for offset in range(-5, 6):  # Scan gateway ±5 addresses
                    try:
                        test_suffix = int(gateway_parts[3]) + offset
                        if 1 <= test_suffix <= 254:
                            test_ip = f"{base_ip}.{test_suffix}"
                            if ipaddress.IPv4Address(test_ip) in network:
                                candidate_ips.append(test_ip)
                    except Exception:
                        continue

                devices.extend(
                    self._scan_candidate_hosts(candidate_ips, "Gateway_Neighbor")
                )

        except Exception as e:
            print(f"Gateway neighbor scan error: {e}")

        return devices

    def _is_in_network_range(self, ip: str) -> bool:
        """Check if IP address is within the current network range."""
        try:
            if hasattr(self, "network_range") and self.network_range:
                network = ipaddress.IPv4Network(self.network_range)
                return ipaddress.IPv4Address(ip) in network
            return True  # If no range set, accept all
        except Exception:
            return False

    def _merge_device_lists(
        self, list1: List[Dict[str, Any]], list2: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merge two device lists, avoiding duplicates."""
        merged = list1.copy()

        for device2 in list2:
            # Check if this device already exists (by IP)
            existing = next((d for d in merged if d["ip"] == device2["ip"]), None)
            if not existing:
                merged.append(device2)
            else:
                # Merge information from both sources
                if device2.get("mac") and device2["mac"] != "Unknown":
                    existing["mac"] = device2["mac"]
                if device2.get("hostname") and device2["hostname"] != "Unknown":
                    existing["hostname"] = device2["hostname"]
                # Add scan method if different
                existing_methods = existing.get("scan_method", "").split(",")
                new_method = device2.get("scan_method", "")
                if new_method and new_method not in existing_methods:
                    existing["scan_method"] = ",".join(existing_methods + [new_method])

        return merged

    def _deduplicate_devices(
        self, devices: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate devices from the list."""
        seen_ips = set()
        unique_devices = []

        for device in devices:
            if device["ip"] not in seen_ips:
                seen_ips.add(device["ip"])
                unique_devices.append(device)

        return unique_devices

    def _enhance_device_info(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enhance device information with additional details."""
        try:
            ip = device["ip"]

            # Get MAC address if not already present
            if not device.get("mac") or device["mac"] == "Unknown":
                mac = self._get_mac_address(ip)
                if mac:
                    device["mac"] = mac

            # Get hostname if not already present
            if not device.get("hostname") or device["hostname"] == "Unknown":
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    device["hostname"] = hostname
                except (socket.herror, socket.gaierror):
                    device["hostname"] = "Unknown"

            vendor = device.get("vendor")
            if not vendor or vendor == "Unknown":
                vendor = self._get_mac_vendor(device.get("mac", ""))

            open_ports = device.get("open_ports", [])
            if self.args.ports and not open_ports:
                open_ports = self._scan_ports(ip)

            device.update(
                {
                    "vendor": vendor or "Unknown",
                    "open_ports": open_ports if self.args.ports else [],
                    "services": (
                        self._identify_services(ip, open_ports)
                        if self.args.ports
                        else {}
                    ),
                    "response_time": device.get(
                        "response_time", device.get("ping_time", 0)
                    ),
                }
            )

            # ---- Enrichment (mDNS, SSDP, NetBIOS, HTTP, TLS) ----
            if getattr(self.args, "enrich", False):
                # Merge pre-collected mDNS results for this IP
                mdns = self.mdns_services.get(ip, [])
                if mdns:
                    device["mdns_services"] = mdns
                    # Pick the best friendly name and model from mDNS
                    for svc in mdns:
                        if "friendly_name" in svc and "friendly_name" not in device:
                            device["friendly_name"] = svc["friendly_name"]
                        if "model" in svc and "model" not in device:
                            device["model"] = svc["model"]
                        if "model_name" in svc and "model_name" not in device:
                            device["model_name"] = svc["model_name"]

                # Merge pre-collected SSDP/UPnP results for this IP
                ssdp = self.ssdp_devices.get(ip, {})
                if ssdp:
                    device["upnp_info"] = ssdp
                    if "upnp_friendly_name" in ssdp and "friendly_name" not in device:
                        device["friendly_name"] = ssdp["upnp_friendly_name"]
                    if "upnp_manufacturer" in ssdp and "manufacturer" not in device:
                        device["manufacturer"] = ssdp["upnp_manufacturer"]
                    if "upnp_model" in ssdp and "model" not in device:
                        device["model"] = ssdp["upnp_model"]
                    if "upnp_serial" in ssdp and "serial_number" not in device:
                        device["serial_number"] = ssdp["upnp_serial"]

                # NetBIOS name (per-host, fast UDP)
                nb_name = self._get_netbios_name(ip)
                if nb_name:
                    device["netbios_name"] = nb_name
                    if "friendly_name" not in device:
                        device["friendly_name"] = nb_name

                # HTTP info – probe ports already known open, or 80/443
                http_ports = [
                    p
                    for p in device.get("open_ports", [])
                    if p in (80, 443, 8080, 8443)
                ]
                if not http_ports:
                    http_ports = [80]  # try default even if port scan was skipped
                for hp in http_ports:
                    http_info = self._get_http_info(ip, hp)
                    if http_info:
                        device.update(
                            {k: v for k, v in http_info.items() if k not in device}
                        )
                        break  # first successful probe is enough

                # TLS certificate info
                tls_ports = [
                    p for p in device.get("open_ports", []) if p in (443, 8443)
                ]
                if not tls_ports:
                    tls_ports = [443]
                for tp in tls_ports:
                    tls_info = self._get_tls_cert_info(ip, tp)
                    if tls_info:
                        device.update(tls_info)
                        break

            # Identify device type last (benefits from enrichment data)
            device["device_type"] = self._identify_device_type(device)

            return device

        except Exception as e:
            if self.verbose:
                print(f"Error enhancing device {device.get('ip', 'unknown')}: {e}")
            return device

    def _track_changes(
        self, current_devices: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Track changes in device list compared to previous scan."""
        # Simple implementation - just return current devices for now
        # Could be enhanced to load previous scan and compare
        return current_devices

    def save_results(self, filename: Optional[str] = None):
        """
        Save scan results to a JSON file.

        Args:
            filename: Output filename. If None, generates timestamped filename.
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.json"

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.devices, f, indent=2)
        print(f"Results saved to: {filename}")

    def export_results(self, format_type: str = "json", filename: Optional[str] = None):
        """
        Export scan results in various formats.

        Args:
            format_type: Export format ('json', 'csv', 'html')
            filename: Output filename. If None, generates timestamped filename.
        """
        if not self.devices:
            print("No devices to export.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format_type == "csv":
            if not filename:
                filename = f"network_scan_{timestamp}.csv"
            self._export_csv(filename)
        elif format_type == "html":
            if not filename:
                filename = f"network_scan_{timestamp}.html"
            self._export_html(filename)
        else:  # Default to JSON
            if not filename:
                filename = f"network_scan_{timestamp}.json"
            self.save_results(filename)

    def _export_csv(self, filename: str):
        """Export results to CSV format."""
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "IP Address",
                    "Hostname",
                    "Friendly Name",
                    "MAC Address",
                    "Vendor",
                    "Manufacturer",
                    "Model",
                    "Serial Number",
                    "Device Type",
                    "NetBIOS Name",
                    "Open Ports",
                    "Services",
                    "mDNS Services",
                    "HTTP Title",
                    "HTTP Server",
                    "TLS Subject CN",
                    "Response Time (ms)",
                    "Last Seen",
                ]
            )

            for ip, info in sorted(
                self.devices.items(), key=lambda x: ipaddress.IPv4Address(x[0])
            ):
                ports_str = ", ".join(map(str, info.get("open_ports", [])))
                services_str = ", ".join(
                    [
                        f"{port}:{service}"
                        for port, service in info.get("services", {}).items()
                    ]
                )
                mdns_str = ", ".join(
                    sorted({s.get("type", "") for s in info.get("mdns_services", [])})
                )
                writer.writerow(
                    [
                        ip,
                        info.get("hostname", ""),
                        info.get("friendly_name", ""),
                        info.get("mac", ""),
                        info.get("vendor", ""),
                        info.get("manufacturer", ""),
                        info.get("model", ""),
                        info.get("serial_number", ""),
                        info.get("device_type", ""),
                        info.get("netbios_name", ""),
                        ports_str,
                        services_str,
                        mdns_str,
                        info.get("http_title", ""),
                        info.get("http_server", ""),
                        info.get("tls_subject_cn", ""),
                        info.get("response_time", ""),
                        info.get("last_seen", ""),
                    ]
                )
        print(f"CSV export saved to: {filename}")

    def _export_html(self, filename: str):
        """Export results to HTML format with enrichment columns."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .device-router {{ background-color: #e3f2fd; }}
                .device-computer {{ background-color: #f3e5f5; }}
                .device-mobile {{ background-color: #e8f5e8; }}
                .device-iot {{ background-color: #fff3e0; }}
                .device-printer {{ background-color: #fce4ec; }}
                .device-speaker {{ background-color: #f3e5f5; }}
                .ping-good {{ color: green; }}
                .ping-slow {{ color: orange; }}
                .ping-bad {{ color: red; }}
                .small {{ font-size: 0.85em; color: #555; }}
            </style>
        </head>
        <body>
            <h1>Network Scan Results</h1>
            <p>Scan performed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total devices found: {len(self.devices)}</p>

            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname / Name</th>
                    <th>MAC Address</th>
                    <th>Vendor / Manufacturer</th>
                    <th>Model</th>
                    <th>Device Type</th>
                    <th>Response Time</th>
                    <th>Open Ports</th>
                    <th>Services</th>
                    <th>Extra Info</th>
                </tr>
        """

        for ip, info in sorted(
            self.devices.items(), key=lambda x: ipaddress.IPv4Address(x[0])
        ):
            device_type = info.get("device_type", "Unknown")
            css_class = ""
            dt_lower = device_type.lower()
            if "router" in dt_lower or "gateway" in dt_lower:
                css_class = "device-router"
            elif "computer" in dt_lower:
                css_class = "device-computer"
            elif "mobile" in dt_lower:
                css_class = "device-mobile"
            elif "iot" in dt_lower or "homekit" in dt_lower:
                css_class = "device-iot"
            elif "printer" in dt_lower:
                css_class = "device-printer"
            elif "speaker" in dt_lower:
                css_class = "device-speaker"

            response_time = info.get("response_time")
            ping_class = ""
            if response_time:
                if response_time < 10:
                    ping_class = "ping-good"
                elif response_time < 100:
                    ping_class = "ping-slow"
                else:
                    ping_class = "ping-bad"

            ports_str = ", ".join(map(str, info.get("open_ports", [])))
            services_str = "<br>".join(
                [
                    f"{port}: {service}"
                    for port, service in info.get("services", {}).items()
                ]
            )
            response_time_str = f"{response_time:.1f}ms" if response_time else "N/A"

            # Build name cell: hostname + friendly name
            name_parts = [info.get("hostname") or "Unknown"]
            friendly = info.get("friendly_name", "")
            nb = info.get("netbios_name", "")
            if friendly:
                name_parts.append(f'<span class="small">{friendly}</span>')
            if nb:
                name_parts.append(f'<span class="small">NetBIOS: {nb}</span>')
            name_cell = "<br>".join(name_parts)

            # Vendor cell: vendor + manufacturer
            vendor_parts = [info.get("vendor") or "Unknown"]
            mfr = info.get("manufacturer", "")
            if mfr and mfr.lower() != (info.get("vendor") or "").lower():
                vendor_parts.append(f'<span class="small">{mfr}</span>')
            vendor_cell = "<br>".join(vendor_parts)

            model_cell = info.get("model", "")

            # Extra info cell
            extras = []
            if info.get("http_title"):
                extras.append(f"HTTP: {info['http_title']}")
            if info.get("http_server"):
                extras.append(f"Server: {info['http_server']}")
            if info.get("tls_subject_cn"):
                extras.append(f"TLS CN: {info['tls_subject_cn']}")
            if info.get("mdns_services"):
                svc_types = sorted({s.get("type", "?") for s in info["mdns_services"]})
                extras.append(f"mDNS: {', '.join(svc_types)}")
            extra_cell = "<br>".join(extras)

            html_content += f"""
                <tr class="{css_class}">
                    <td>{ip}</td>
                    <td>{name_cell}</td>
                    <td>{info.get('mac', 'Unknown')}</td>
                    <td>{vendor_cell}</td>
                    <td>{model_cell}</td>
                    <td>{device_type}</td>
                    <td class="{ping_class}">{response_time_str}</td>
                    <td>{ports_str}</td>
                    <td>{services_str}</td>
                    <td class="small">{extra_cell}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"HTML report saved to: {filename}")

    def show_device_history(self):
        """Display device change history from previous scans."""
        history = self._load_device_history()

        if not history.get("scan_history"):
            print("No scan history available.")
            return

        print(f"\n{'='*80}")
        print("DEVICE SCAN HISTORY")
        print(f"{'='*80}")

        scan_history = history["scan_history"][-10:]  # Show last 10 scans

        for scan in scan_history:
            timestamp = datetime.fromisoformat(scan["timestamp"])
            changes = scan["changes"]

            print(f"\nScan: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Devices found: {scan['device_count']}")

            if changes["new_devices"]:
                print(f"  New devices: {len(changes['new_devices'])}")
                for device in changes["new_devices"][:3]:  # Show first 3
                    print(f"    + {device['ip']} ({device['device_type']})")
                if len(changes["new_devices"]) > 3:
                    print(f"    ... and {len(changes['new_devices']) - 3} more")

            if changes["missing_devices"]:
                print(f"  Missing devices: {len(changes['missing_devices'])}")
                for device in changes["missing_devices"][:3]:
                    print(f"    - {device['ip']}")
                if len(changes["missing_devices"]) > 3:
                    print(f"    ... and {len(changes['missing_devices']) - 3} more")

            if changes["changed_devices"]:
                print(f"  Security alerts: {len(changes['changed_devices'])}")
                for device in changes["changed_devices"]:
                    print(f"    ! {device['ip']} MAC changed")

        print(
            f"\nShowing last {len(scan_history)} scans. Full history saved in {self.history_file}"
        )

    def print_results(self, show_ports: bool = False, show_services: bool = False):
        """
        Display scan results in a formatted, human-readable table.

        Args:
            show_ports: Whether to include open ports in the output
            show_services: Whether to include service identification
        """
        if not self.devices:
            print("No devices found.")
            return

        print(f"\n{'='*80}")
        print(f"NETWORK SCAN RESULTS - {len(self.devices)} devices found")
        print(f"{'='*80}")

        # Sort devices by IP address for logical ordering
        sorted_devices = sorted(
            self.devices.items(), key=lambda x: ipaddress.IPv4Address(x[0])
        )

        for ip, info in sorted_devices:
            print(f"\nIP Address:  {ip}")
            print(f"Hostname:    {info['hostname'] or 'Unknown'}")
            print(f"MAC:         {info['mac'] or 'Unknown'}")
            print(f"Vendor:      {info['vendor'] or 'Unknown'}")
            print(f"Device Type: {info.get('device_type', 'Unknown')}")

            # Enrichment fields
            if info.get("friendly_name"):
                print(f"Name:        {info['friendly_name']}")
            if info.get("manufacturer"):
                print(f"Manufacturer:{info['manufacturer']}")
            if info.get("model"):
                print(f"Model:       {info['model']}")
            if info.get("serial_number"):
                print(f"Serial #:    {info['serial_number']}")
            if info.get("netbios_name"):
                print(f"NetBIOS:     {info['netbios_name']}")
            if info.get("http_title"):
                print(f"HTTP Title:  {info['http_title']}")
            if info.get("http_server"):
                print(f"HTTP Server: {info['http_server']}")
            if info.get("tls_subject_cn"):
                print(f"TLS Cert CN: {info['tls_subject_cn']}")
            if info.get("tls_issuer"):
                print(f"TLS Issuer:  {info['tls_issuer']}")

            # mDNS services summary
            if info.get("mdns_services"):
                svc_types = sorted({s.get("type", "?") for s in info["mdns_services"]})
                print(f"mDNS:        {', '.join(svc_types)}")

            # Show response time if available
            response_time = info.get("response_time")
            if response_time is not None:
                print(f"Ping Time:   {response_time:.1f}ms")

            # Show open ports if requested and available
            if show_ports and info.get("open_ports"):
                ports_str = ", ".join(map(str, info["open_ports"]))
                print(f"Open Ports: {ports_str}")

            # Show services if requested and available
            if show_services and info.get("services"):
                print("Services:")
                for port, service in info["services"].items():
                    print(f"  Port {port}: {service}")

            print(f"Last Seen:  {info['last_seen']}")
            print("-" * 40)


# ============================================================================
# Main CLI Application
# ============================================================================


def main():
    """
    Main entry point for the network scanner CLI application.

    Parses command line arguments, configures the scanner, and runs the scan
    with appropriate options. Handles user interruption gracefully.
    """
    parser = argparse.ArgumentParser(
        description="WiFi Network Device Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Scan default network
  %(prog)s -n 192.168.0.0/24        # Scan specific network
  %(prog)s -p                       # Include port scanning
  %(prog)s -p --show-services       # Include detailed service identification
  %(prog)s --enrich                 # Deep device enrichment (mDNS, UPnP, NetBIOS, HTTP, TLS)
  %(prog)s --enrich -p --export html # Full scan with enrichment, ports, and HTML report
  %(prog)s -t 0.5 -T 100            # Fast scan with custom timeout/threads
  %(prog)s -s results.json          # Save results to file
  %(prog)s --export csv             # Export results to CSV
  %(prog)s --export html            # Export results to HTML report
  %(prog)s --history                # Show device change history
        """,
    )

    # Define command line arguments
    parser.add_argument(
        "-n", "--network", help="Network range to scan (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Ping timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=50,
        help="Number of scanning threads (default: 50)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        action="store_true",
        help="Scan for open ports on discovered devices",
    )
    parser.add_argument("-s", "--save", help="Save results to JSON file")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress progress output"
    )
    parser.add_argument(
        "--export",
        choices=["json", "csv", "html"],
        help="Export results in specified format",
    )
    parser.add_argument("--export-file", help="Specify export filename")
    parser.add_argument(
        "--show-services",
        action="store_true",
        help="Show detailed service information for open ports",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show device change history from previous scans",
    )
    parser.add_argument(
        "--arp-scan",
        action="store_true",
        help="Use ARP scanning in addition to ping (may find more devices)",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Use aggressive scanning methods for mesh networks",
    )
    parser.add_argument(
        "--detect-networks",
        action="store_true",
        help="Show all detected network interfaces and ranges",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Enable deep device enrichment: mDNS/Bonjour, SSDP/UPnP, "
        "NetBIOS, HTTP title/server, and TLS certificate info",
    )

    args = parser.parse_args()

    try:
        # Initialize scanner with user-specified or default settings
        scanner = NetworkScanner(
            network_range=args.network,
            timeout=args.timeout,
            max_threads=args.threads,
            verbose=not args.quiet,
            args=args,
        )

        # Show history if requested
        if args.history:
            scanner.show_device_history()
            return

        print("Starting network scan...")
        start_time = time.time()

        # Perform the network scan
        devices = scanner.scan_network(custom_range=args.network)

        # Calculate and display scan duration
        end_time = time.time()
        scan_duration = end_time - start_time
        print(f"\nScan completed in {scan_duration:.2f} seconds")

        # Display results in formatted table
        scanner.print_results(show_ports=args.ports, show_services=args.show_services)

        # Save results to file if requested
        if args.save:
            scanner.save_results(args.save)

        # Export results if requested
        if args.export:
            scanner.export_results(args.export, args.export_file)

        print(f"\nSummary: Found {len(devices)} active devices")

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except (OSError, ValueError, FileNotFoundError) as e:
        print(f"Error: {e}")
        sys.exit(1)


# ============================================================================
# Script Entry Point
# ============================================================================

if __name__ == "__main__":
    main()
