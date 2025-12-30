"""
Input validation utilities for terminal-based IP and port entry.

Provides comprehensive validation for network address input from terminal.
"""

import re
from typing import Tuple


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IPv4 address format.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IPv4 address, False otherwise
        
    Raises:
        ValueError: If IP contains invalid characters
    """
    # Check for empty string
    if not ip or not ip.strip():
        return False
    
    # IPv4 regex pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if not re.match(ipv4_pattern, ip):
        return False
    
    # Validate each octet is 0-255
    octets = ip.split('.')
    for octet in octets:
        try:
            num = int(octet)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    
    return True


def validate_port(port: str) -> bool:
    """
    Validate a port number.
    
    Args:
        port: Port number string to validate
        
    Returns:
        True if valid port, False otherwise
        
    Raises:
        ValueError: If port is not a valid integer
    """
    # Check for empty string
    if not port or not port.strip():
        return False
    
    try:
        port_num = int(port)
        # Valid port range: 1-65535
        return 1 <= port_num <= 65535
    except ValueError:
        return False


def get_ip_from_input(prompt: str = "Enter server IP address", default: str = "127.0.0.1") -> str:
    """
    Get and validate an IP address from terminal input.
    
    Args:
        prompt: Prompt message to display
        default: Default IP if user just presses Enter
        
    Returns:
        Validated IP address string
    """
    while True:
        user_input = input(f"{prompt} [default = {default}]: ").strip()
        
        # Use default if empty input
        if not user_input:
            user_input = default
        
        # Validate
        if validate_ip_address(user_input):
            return user_input
        else:
            print(f"Invalid IP address: '{user_input}'")
            print(f"Please enter a valid IPv4 address (e.g., 127.0.0.1)")


def get_port_from_input(prompt: str = "Enter port number", default: int = 5000) -> int:
    """
    Get and validate a port number from terminal input.
    
    Args:
        prompt: Prompt message to display
        default: Default port if user just presses Enter
        
    Returns:
        Validated port number as integer
    """
    while True:
        user_input = input(f"{prompt} [default = {default}]: ").strip()
        
        # Use default if empty input
        if not user_input:
            user_input = str(default)
        
        # Validate
        if validate_port(user_input):
            return int(user_input)
        else:
            print(f"Invalid port number: '{user_input}'")
            print(f"Please enter a port number between 1 and 65535")


def get_network_config(server_mode: bool = False) -> Tuple[str, int]:
    """
    Get network configuration (IP and port) from user input with validation.
    
    Args:
        server_mode: If True, prompt for server config; if False, for client config
        
    Returns:
        Tuple of (host, port)
    """
    if server_mode:
        print("\n" + "="*60)
        print("SERVER CONFIGURATION")
        print("="*60)
        # For server, default to all interfaces
        host = get_ip_from_input("Enter binding IP address", "127.0.0.1")
    else:
        print("\n" + "="*60)
        print("CLIENT CONFIGURATION")
        print("="*60)
        # For client, default to localhost
        host = get_ip_from_input("Enter server IP address", "127.0.0.1")
    
    port = get_port_from_input("Enter port number", 5000)
    
    print(f"Configuration validated: {host}:{port}\n")
    
    return host, port


__all__ = [
    'validate_ip_address',
    'validate_port',
    'get_ip_from_input',
    'get_port_from_input',
    'get_network_config'
]
