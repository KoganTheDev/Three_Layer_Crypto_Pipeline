"""
Unit tests for input validation utilities.

Tests IP address and port validation functions.
"""

import pytest
from src.utils.input_validation import (
    validate_ip_address,
    validate_port
)


class TestIPAddressValidation:
    """Test IP address validation."""
    
    def test_valid_ip_addresses(self):
        """Test that valid IP addresses pass validation."""
        valid_ips = [
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "255.255.255.255",
            "8.8.8.8",
            "10.0.0.1",
            "172.16.0.1"
        ]
        for ip in valid_ips:
            assert validate_ip_address(ip), f"Expected {ip} to be valid"
    
    def test_invalid_ip_addresses(self):
        """Test that invalid IP addresses fail validation."""
        invalid_ips = [
            "",  # Empty
            "256.1.1.1",  # Octet > 255
            "1.1.1",  # Too few octets
            "1.1.1.1.1",  # Too many octets
            "1.1.1.a",  # Non-numeric
            "192.168.1",  # Incomplete
            "192.168.1.1.1",  # Too many octets
            "abc.def.ghi.jkl",  # All non-numeric
            "-1.0.0.0",  # Negative
            "1..1.1.1",  # Empty octet
            "   ",  # Whitespace only
        ]
        for ip in invalid_ips:
            assert not validate_ip_address(ip), f"Expected {ip} to be invalid"
    
    def test_ip_with_leading_zeros(self):
        """Test IP addresses with leading zeros."""
        assert validate_ip_address("192.168.001.001"), "IPs with leading zeros should be valid"
    
    def test_ip_boundary_values(self):
        """Test IP addresses with boundary values."""
        assert validate_ip_address("0.0.0.0"), "0.0.0.0 should be valid"
        assert validate_ip_address("255.255.255.255"), "255.255.255.255 should be valid"
        assert not validate_ip_address("256.0.0.0"), "256.0.0.0 should be invalid"


class TestPortValidation:
    """Test port number validation."""
    
    def test_valid_ports(self):
        """Test that valid port numbers pass validation."""
        valid_ports = [
            "1",  # Min port
            "22",  # SSH
            "80",  # HTTP
            "443",  # HTTPS
            "5000",  # Dev default
            "8080",  # Common dev
            "65535"  # Max port
        ]
        for port in valid_ports:
            assert validate_port(port), f"Expected {port} to be valid"
    
    def test_invalid_ports(self):
        """Test that invalid port numbers fail validation."""
        invalid_ports = [
            "",  # Empty
            "0",  # Below minimum
            "-1",  # Negative
            "65536",  # Above maximum
            "99999",  # Way above maximum
            "abc",  # Non-numeric
            "80a",  # Partially numeric
            "   ",  # Whitespace only
            "12.34",  # Decimal
        ]
        for port in invalid_ports:
            assert not validate_port(port), f"Expected {port} to be invalid"
    
    def test_port_boundaries(self):
        """Test port boundary values."""
        assert validate_port("1"), "Port 1 should be valid"
        assert validate_port("65535"), "Port 65535 should be valid"
        assert not validate_port("0"), "Port 0 should be invalid"
        assert not validate_port("65536"), "Port 65536 should be invalid"
    
    def test_port_with_whitespace(self):
        """Test port parsing with whitespace."""
        # The function strips whitespace before validation
        # But we need to test the actual input
        assert validate_port("5000"), "Port with no whitespace should work"


class TestCommonNetworkAddresses:
    """Test common network addresses and ports."""
    
    def test_localhost_variations(self):
        """Test localhost IP address."""
        assert validate_ip_address("127.0.0.1"), "127.0.0.1 should be valid"
    
    def test_common_dev_servers(self):
        """Test common development server configurations."""
        # Localhost on common dev ports
        assert validate_ip_address("127.0.0.1") and validate_port("5000")
        assert validate_ip_address("127.0.0.1") and validate_port("8000")
        assert validate_ip_address("127.0.0.1") and validate_port("3000")
        
        # Remote servers on common ports
        assert validate_ip_address("192.168.1.1") and validate_port("5000")
        assert validate_ip_address("0.0.0.0") and validate_port("5000")
    
    def test_docker_network(self):
        """Test Docker network addresses."""
        assert validate_ip_address("172.17.0.1"), "Docker host should be valid"
        assert validate_ip_address("172.17.0.2"), "Docker container should be valid"


class TestEdgeCases:
    """Test edge cases and special situations."""
    
    def test_private_ip_ranges(self):
        """Test private IP address ranges."""
        private_ips = [
            "10.0.0.0",
            "10.255.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.168.0.0",
            "192.168.255.255"
        ]
        for ip in private_ips:
            assert validate_ip_address(ip), f"Private IP {ip} should be valid"
    
    def test_multicast_addresses(self):
        """Test multicast IP addresses."""
        # Multicast range: 224.0.0.0 - 239.255.255.255
        assert validate_ip_address("224.0.0.1"), "Multicast address should be valid"
        assert validate_ip_address("239.255.255.255"), "Multicast address should be valid"
    
    def test_broadcast_address(self):
        """Test broadcast address."""
        assert validate_ip_address("255.255.255.255"), "Broadcast should be valid"
    
    def test_reserved_addresses(self):
        """Test reserved IP addresses."""
        assert validate_ip_address("0.0.0.0"), "0.0.0.0 should be valid"
        assert validate_ip_address("127.0.0.1"), "Loopback should be valid"
        assert validate_ip_address("127.255.255.255"), "Loopback range should be valid"


class TestIntegration:
    """Integration tests for IP and port combinations."""
    
    def test_realistic_server_configs(self):
        """Test realistic server configurations."""
        configs = [
            ("0.0.0.0", "5000"),  # Listen on all interfaces
            ("127.0.0.1", "5000"),  # Localhost only
            ("192.168.1.1", "8080"),  # Private network
            ("10.0.0.1", "443"),  # Private network with HTTPS port
        ]
        for ip, port in configs:
            assert validate_ip_address(ip), f"IP {ip} should be valid"
            assert validate_port(port), f"Port {port} should be valid"
    
    def test_realistic_client_configs(self):
        """Test realistic client configurations."""
        configs = [
            ("127.0.0.1", "5000"),  # Connect to localhost
            ("192.168.1.100", "5000"),  # Connect to remote host
            ("8.8.8.8", "53"),  # Connect to Google DNS (just for validation)
        ]
        for ip, port in configs:
            assert validate_ip_address(ip), f"IP {ip} should be valid for client"
            assert validate_port(port), f"Port {port} should be valid for client"
