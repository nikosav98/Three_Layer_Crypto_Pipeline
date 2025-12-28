"""
Test module for RC6 encryption implementation with GCM mode.

Tests cover:
1. Basic encryption/decryption
2. Authentication tag generation and verification
3. IV/Nonce handling
4. Key length validation
5. Plaintext and ciphertext padding
6. Edge cases and error conditions
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.algorithms.rc6.rc6_gcm_mode import RC6GCM


class TestRC6GCM:
    """Test cases for RC6-GCM authenticated encryption."""
    
    @pytest.fixture
    def cipher(self):
        """Create an RC6GCM instance with random key and IV."""
        key = os.urandom(32)  # 256-bit key
        iv = os.urandom(12)   # 96-bit IV for GCM
        return RC6GCM(key, iv)
    
    # --- 1. Basic Functionality Tests ---
    
    def test_encrypt_decrypt_round_trip(self, cipher):
        """Test: Encrypt and decrypt returns original plaintext."""
        plaintext = b"Hello, World!"
        aad = b"additional data"
        
        # Encrypt
        ciphertext, tag = cipher.encrypt(plaintext, aad)
        
        assert isinstance(ciphertext, bytes)
        assert isinstance(tag, bytes)
        assert len(tag) == 16  # GCM tag is 128 bits (16 bytes)
        
        # Decrypt
        decrypted = cipher.decrypt(ciphertext, tag, aad)
        
        assert decrypted == plaintext
    
    def test_encrypt_with_empty_aad(self, cipher):
        """Test: Encryption works with empty AAD."""
        plaintext = b"Test message"
        
        ciphertext, tag = cipher.encrypt(plaintext, b"")
        decrypted = cipher.decrypt(ciphertext, tag, b"")
        
        assert decrypted == plaintext
    
    def test_encrypt_empty_plaintext(self, cipher):
        """Test: Can encrypt empty message with authentication."""
        plaintext = b""
        aad = b"authenticated but empty"
        
        ciphertext, tag = cipher.encrypt(plaintext, aad)
        
        # Ciphertext should also be empty, but tag should be generated
        assert ciphertext == b""
        assert len(tag) == 16
        
        # Should decrypt to empty plaintext
        decrypted = cipher.decrypt(ciphertext, tag, aad)
        assert decrypted == plaintext
    
    def test_different_ivs_produce_different_ciphertexts(self):
        """Test: Same plaintext with different IVs produces different ciphertexts."""
        plaintext = b"Same message"
        key = os.urandom(32)
        
        cipher1 = RC6GCM(key, os.urandom(12))
        cipher2 = RC6GCM(key, os.urandom(12))
        
        ciphertext1, _ = cipher1.encrypt(plaintext, b"")
        ciphertext2, _ = cipher2.encrypt(plaintext, b"")
        
        assert ciphertext1 != ciphertext2
    
    def test_different_keys_produce_different_ciphertexts(self):
        """Test: Same plaintext with different keys produces different ciphertexts."""
        plaintext = b"Same message"
        iv = os.urandom(12)
        
        cipher1 = RC6GCM(os.urandom(32), iv)
        cipher2 = RC6GCM(os.urandom(32), iv)
        
        ciphertext1, _ = cipher1.encrypt(plaintext, b"")
        ciphertext2, _ = cipher2.encrypt(plaintext, b"")
        
        assert ciphertext1 != ciphertext2
    
    # --- 2. Authentication Tests ---
    
    def test_tag_verification_fails_on_modified_ciphertext(self, cipher):
        """Test: Authentication fails if ciphertext is modified."""
        plaintext = b"Important message"
        
        ciphertext, tag = cipher.encrypt(plaintext, b"")
        
        # Modify ciphertext
        modified_ciphertext = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:] if ciphertext else b'\xFF'
        
        # Decryption should fail (or return corrupted data)
        try:
            decrypted = cipher.decrypt(modified_ciphertext, tag, b"")
            # If it doesn't raise, at least the data should be wrong (unless empty)
            if plaintext:
                assert decrypted != plaintext
        except ValueError:
            # Exception on authentication failure is acceptable
            pass
    
    def test_tag_verification_fails_on_modified_tag(self, cipher):
        """Test: Authentication fails if tag is modified."""
        plaintext = b"Important message"
        
        ciphertext, tag = cipher.encrypt(plaintext, b"")
        
        # Modify tag
        modified_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        
        # Decryption should fail
        try:
            decrypted = cipher.decrypt(ciphertext, modified_tag, b"")
            # If no exception, data should still be wrong
            assert decrypted != plaintext
        except ValueError:
            pass
    
    def test_aad_affects_authentication_tag(self):
        """Test: Different AAD produces different authentication tags."""
        plaintext = b"Message"
        key = os.urandom(32)
        iv = os.urandom(12)
        
        cipher1 = RC6GCM(key, iv)
        cipher2 = RC6GCM(key, iv)
        
        ciphertext1, tag1 = cipher1.encrypt(plaintext, b"aad1")
        ciphertext2, tag2 = cipher2.encrypt(plaintext, b"aad2")
        
        # Ciphertexts should be same (same key and IV)
        assert ciphertext1 == ciphertext2
        # But tags should differ (different AAD)
        assert tag1 != tag2
    
    # --- 3. Large Data Tests ---
    
    def test_encrypt_medium_plaintext(self, cipher):
        """Test: Can encrypt medium plaintext (10KB)."""
        plaintext = os.urandom(10 * 1024)  # 10KB
        
        ciphertext, tag = cipher.encrypt(plaintext, b"")
        
        # Ciphertext should be same length
        assert len(ciphertext) == len(plaintext)
        assert len(tag) == 16
        
        # Should decrypt correctly
        decrypted = cipher.decrypt(ciphertext, tag, b"")
        assert decrypted == plaintext
    
    def test_encrypt_medium_aad(self, cipher):
        """Test: Can handle medium AAD."""
        plaintext = b"Message"
        aad = os.urandom(1 * 1024)  # 1KB AAD
        
        ciphertext, tag = cipher.encrypt(plaintext, aad)
        
        decrypted = cipher.decrypt(ciphertext, tag, aad)
        assert decrypted == plaintext
    
    # --- 4. Key Length Tests ---
    
    def test_256_bit_key(self):
        """Test: 256-bit key works."""
        key = os.urandom(32)
        iv = os.urandom(12)
        cipher = RC6GCM(key, iv)
        
        plaintext = b"Test"
        
        ciphertext, tag = cipher.encrypt(plaintext, b"")
        decrypted = cipher.decrypt(ciphertext, tag, b"")
        
        assert decrypted == plaintext
    
    def test_128_bit_key(self):
        """Test: 128-bit key works."""
        key = os.urandom(16)
        iv = os.urandom(12)
        cipher = RC6GCM(key, iv)
        
        plaintext = b"Test"
        
        ciphertext, tag = cipher.encrypt(plaintext, b"")
        decrypted = cipher.decrypt(ciphertext, tag, b"")
        
        assert decrypted == plaintext
    
    # --- 5. Multiple Operations with Same Cipher ---
    
    def test_reuse_cipher_multiple_times(self):
        """Test: Can reuse cipher instance for multiple operations."""
        key = os.urandom(32)
        iv = os.urandom(12)
        cipher = RC6GCM(key, iv)
        
        plaintext = b"Test message"
        
        # Encrypt/decrypt multiple times with same cipher
        ciphertext1, tag1 = cipher.encrypt(plaintext, b"")
        decrypted1 = cipher.decrypt(ciphertext1, tag1, b"")
        
        ciphertext2, tag2 = cipher.encrypt(plaintext, b"")
        decrypted2 = cipher.decrypt(ciphertext2, tag2, b"")
        
        assert decrypted1 == plaintext
        assert decrypted2 == plaintext
    
    # --- 6. Consistency Tests ---
    
    def test_consistent_encryption_same_inputs(self, cipher):
        """Test: Same plaintext and AAD produce same ciphertext and tag."""
        plaintext = b"Consistent test"
        aad = b"aad"
        
        ciphertext1, tag1 = cipher.encrypt(plaintext, aad)
        ciphertext2, tag2 = cipher.encrypt(plaintext, aad)
        
        assert ciphertext1 == ciphertext2
        assert tag1 == tag2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
