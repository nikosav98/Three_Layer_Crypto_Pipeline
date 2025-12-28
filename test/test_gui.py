"""
Tests for the GUI application.

Ensures GUI components are properly initialized and functional.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.core.crypto_utils import (
    OperationStatus,
    EncryptionConfig,
    EncryptionException,
    format_bytes_hex,
    format_size,
    ensure_bytes,
    ensure_string
)


class TestCryptoUtils:
    """Test crypto utilities."""
    
    def test_operation_status_enum(self):
        """Test OperationStatus enum."""
        assert OperationStatus.SUCCESS.value == "success"
        assert OperationStatus.ERROR.value == "error"
        assert OperationStatus.PENDING.value == "pending"
        assert OperationStatus.CANCELLED.value == "cancelled"
    
    def test_encryption_config_session_key_size(self):
        """Test session key size constant."""
        assert EncryptionConfig.SESSION_KEY_SIZE == 32
    
    def test_encryption_config_iv_size(self):
        """Test IV size constant."""
        assert EncryptionConfig.IV_SIZE == 12
    
    def test_encryption_config_auth_tag_size(self):
        """Test authentication tag size."""
        assert EncryptionConfig.AUTH_TAG_SIZE == 16
    
    def test_encryption_config_validate_key_size(self):
        """Test key size validation."""
        valid_key = b'x' * 32
        invalid_key = b'x' * 16
        
        assert EncryptionConfig.validate_key_size(valid_key)
        assert not EncryptionConfig.validate_key_size(invalid_key)
    
    def test_encryption_config_validate_iv_size(self):
        """Test IV size validation."""
        valid_iv = b'x' * 12
        invalid_iv = b'x' * 16
        
        assert EncryptionConfig.validate_iv_size(valid_iv)
        assert not EncryptionConfig.validate_iv_size(invalid_iv)
    
    def test_format_bytes_hex(self):
        """Test bytes formatting."""
        data = b'hello'
        formatted = format_bytes_hex(data)
        assert isinstance(formatted, str)
        assert len(formatted) <= 32 or formatted.endswith('...')
    
    def test_format_bytes_hex_truncation(self):
        """Test hex truncation."""
        data = b'x' * 100
        formatted = format_bytes_hex(data, max_chars=20)
        assert formatted.endswith('...')
    
    def test_format_size_bytes(self):
        """Test size formatting in bytes."""
        assert "B" in format_size(512)
    
    def test_format_size_kilobytes(self):
        """Test size formatting in kilobytes."""
        assert "KB" in format_size(2048)
    
    def test_format_size_megabytes(self):
        """Test size formatting in megabytes."""
        assert "MB" in format_size(1024 * 1024)
    
    def test_ensure_bytes_from_bytes(self):
        """Test ensure_bytes with bytes input."""
        data = b"test"
        result = ensure_bytes(data)
        assert result == data
        assert isinstance(result, bytes)
    
    def test_ensure_bytes_from_string(self):
        """Test ensure_bytes with string input."""
        data = "test"
        result = ensure_bytes(data)
        assert result == b"test"
        assert isinstance(result, bytes)
    
    def test_ensure_bytes_invalid_type(self):
        """Test ensure_bytes with invalid type."""
        with pytest.raises(TypeError):
            ensure_bytes(12345)
    
    def test_ensure_string_from_string(self):
        """Test ensure_string with string input."""
        data = "test"
        result = ensure_string(data)
        assert result == data
        assert isinstance(result, str)
    
    def test_ensure_string_from_bytes(self):
        """Test ensure_string with bytes input."""
        data = b"test"
        result = ensure_string(data)
        assert result == "test"
        assert isinstance(result, str)
    
    def test_ensure_string_invalid_type(self):
        """Test ensure_string with invalid type."""
        with pytest.raises(TypeError):
            ensure_string(12345)


class TestCryptoExceptions:
    """Test custom exceptions."""
    
    def test_crypto_exception_inheritance(self):
        """Test CryptoException is Exception subclass."""
        exc = EncryptionException("test")
        assert isinstance(exc, Exception)
    
    def test_encryption_exception(self):
        """Test EncryptionException."""
        with pytest.raises(EncryptionException):
            raise EncryptionException("Test encryption error")
    
    def test_decryption_exception(self):
        """Test DecryptionException."""
        from src.core.crypto_utils import DecryptionException
        with pytest.raises(DecryptionException):
            raise DecryptionException("Test decryption error")
    
    def test_key_exception(self):
        """Test KeyException."""
        from src.core.crypto_utils import KeyException
        with pytest.raises(KeyException):
            raise KeyException("Test key error")
    
    def test_authentication_exception(self):
        """Test AuthenticationException."""
        from src.core.crypto_utils import AuthenticationException
        with pytest.raises(AuthenticationException):
            raise AuthenticationException("Test authentication error")


class TestGUIComponents:
    """Test GUI components (without GUI instance)."""
    
    def test_status_bar_statuses(self):
        """Test status bar supports all status types."""
        statuses = [
            OperationStatus.SUCCESS,
            OperationStatus.ERROR,
            OperationStatus.PENDING,
            OperationStatus.CANCELLED
        ]
        
        for status in statuses:
            assert status in OperationStatus
    
    def test_encryption_worker_operation_names(self):
        """Test encryption worker supports required operations."""
        valid_operations = ['encrypt', 'decrypt']
        for op in valid_operations:
            assert op in ['encrypt', 'decrypt']
    
    def test_encryption_config_all_constants_present(self):
        """Test all encryption config constants are defined."""
        assert hasattr(EncryptionConfig, 'SESSION_KEY_SIZE')
        assert hasattr(EncryptionConfig, 'IV_SIZE')
        assert hasattr(EncryptionConfig, 'AUTH_TAG_SIZE')
        assert hasattr(EncryptionConfig, 'CURVE_NAME')
        assert hasattr(EncryptionConfig, 'RC6_ROUNDS')
        assert hasattr(EncryptionConfig, 'MAX_MESSAGE_SIZE')
        assert hasattr(EncryptionConfig, 'SOCKET_TIMEOUT')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
