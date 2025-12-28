"""
Core utilities and constants for the cryptographic system.

This module provides shared utilities used across the entire project.
"""

import os
from enum import Enum
from typing import Tuple, Optional


class OperationStatus(Enum):
    """Status enumeration for operations."""
    SUCCESS = "success"
    PENDING = "pending"
    ERROR = "error"
    CANCELLED = "cancelled"


class EncryptionConfig:
    """Configuration constants for encryption algorithms."""
    
    # Key sizes (bytes)
    SESSION_KEY_SIZE = 32  # 256-bit
    IV_SIZE = 12  # 96-bit for GCM
    AUTH_TAG_SIZE = 16  # 128-bit
    
    # Curve parameters
    CURVE_NAME = "SECP256K1"
    KEY_COORDINATE_SIZE = 32  # 256-bit
    
    # RC6 parameters
    RC6_ROUNDS = 32
    RC6_BLOCK_SIZE = 16  # 128-bit in bytes
    
    # Network parameters
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB
    SOCKET_TIMEOUT = 30  # seconds
    
    @staticmethod
    def validate_key_size(key: bytes) -> bool:
        """Validate session key size."""
        return len(key) == EncryptionConfig.SESSION_KEY_SIZE
    
    @staticmethod
    def validate_iv_size(iv: bytes) -> bool:
        """Validate IV size."""
        return len(iv) == EncryptionConfig.IV_SIZE


class CryptoException(Exception):
    """Base exception for cryptographic operations."""
    pass


class EncryptionException(CryptoException):
    """Raised when encryption fails."""
    pass


class DecryptionException(CryptoException):
    """Raised when decryption fails."""
    pass


class KeyException(CryptoException):
    """Raised when key generation or validation fails."""
    pass


class AuthenticationException(CryptoException):
    """Raised when authentication fails."""
    pass


def get_project_root() -> str:
    """
    Get the project root directory.
    
    Returns:
        Absolute path to project root
    """
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ensure_bytes(data) -> bytes:
    """
    Ensure data is bytes.
    
    Args:
        data: String or bytes
        
    Returns:
        bytes: Data as bytes
        
    Raises:
        TypeError: If data cannot be converted to bytes
    """
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        return data.encode('utf-8')
    else:
        raise TypeError(f"Cannot convert {type(data)} to bytes")


def ensure_string(data) -> str:
    """
    Ensure data is a string.
    
    Args:
        data: Bytes or string
        
    Returns:
        str: Data as string
        
    Raises:
        TypeError: If data cannot be converted to string
    """
    if isinstance(data, str):
        return data
    elif isinstance(data, bytes):
        return data.decode('utf-8', errors='replace')
    else:
        raise TypeError(f"Cannot convert {type(data)} to string")


def format_bytes_hex(data: bytes, max_chars: int = 32) -> str:
    """
    Format bytes as hex string for display.
    
    Args:
        data: Bytes to format
        max_chars: Maximum characters to display (with ellipsis if exceeded)
        
    Returns:
        str: Formatted hex string
    """
    hex_str = data.hex()
    if len(hex_str) > max_chars:
        return hex_str[:max_chars] + "..."
    return hex_str


def format_size(size_bytes: int) -> str:
    """
    Format byte size as human-readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        str: Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
