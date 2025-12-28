"""
Integration tests for complete cryptographic pipeline.

Tests the full workflow:
1. ExchangeManager encryption (Schnorr + RC6-GCM)
2. Network message transmission
3. ExchangeManager decryption and verification
"""

import pytest
import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.key_pair import KeyPair
from src.utils.email_message import EmailMessage
from src.algorithms.key_exchange.exchange_manager import ExchangeManager
from src.algorithms.schnorr.schnorr_signature import SchnorrSigner
from src.algorithms.rc6.rc6_gcm_mode import RC6GCM


class TestExchangeManager:
    """Test ExchangeManager complete pipeline."""
    
    def test_generate_session_key(self):
        """Test session key generation."""
        sender_priv, sender_pub = KeyPair.generate()
        recipient_priv, recipient_pub = KeyPair.generate()
        
        manager = ExchangeManager(sender_priv, recipient_pub)
        key = manager.generate_session_key()
        
        assert len(key) == 32, "Session key should be 32 bytes"
        assert isinstance(key, bytes), "Session key should be bytes"
    
    def test_generate_iv(self):
        """Test IV generation."""
        sender_priv, sender_pub = KeyPair.generate()
        recipient_priv, recipient_pub = KeyPair.generate()
        
        manager = ExchangeManager(sender_priv, recipient_pub)
        iv = manager.generate_iv()
        
        assert len(iv) == 12, "IV should be 12 bytes"
        assert isinstance(iv, bytes), "IV should be bytes"
    
    def test_secure_send_encrypt(self):
        """Test secure_send encryption."""
        sender_priv, sender_pub = KeyPair.generate()
        recipient_priv, recipient_pub = KeyPair.generate()
        
        manager = ExchangeManager(sender_priv, recipient_pub)
        message = EmailMessage("Hello, World!")
        
        bundle = manager.secure_send(message)
        
        # Verify bundle contents
        assert bundle is not None, "Bundle should not be None"
        assert bundle.ciphertext is not None, "Ciphertext should not be None"
        assert bundle.auth_tag is not None, "Auth tag should not be None"
        assert bundle.iv is not None, "IV should not be None"
        assert len(bundle.auth_tag) == 16, "Auth tag should be 16 bytes"
        assert len(bundle.iv) == 12, "IV should be 12 bytes"
    
    def test_secure_send_receive_roundtrip(self):
        """Test complete send/receive roundtrip."""
        sender_priv, sender_pub = KeyPair.generate()
        recipient_priv, recipient_pub = KeyPair.generate()
        
        # Sender encrypts
        sender_manager = ExchangeManager(sender_priv, recipient_pub)
        message_text = "Secret message from Alice!"
        message = EmailMessage(message_text)
        bundle = sender_manager.secure_send(message)
        
        # Receiver decrypts
        receiver_manager = ExchangeManager(recipient_priv, sender_pub)
        decrypted = receiver_manager.secure_receive(bundle, recipient_priv)
        
        assert decrypted == message_text, "Decrypted message should match original"
    
    def test_signature_verification_fails_on_tampering(self):
        """Test that tampering is detected."""
        sender_priv, sender_pub = KeyPair.generate()
        recipient_priv, recipient_pub = KeyPair.generate()
        
        # Sender encrypts
        sender_manager = ExchangeManager(sender_priv, recipient_pub)
        message = EmailMessage("Important message")
        bundle = sender_manager.secure_send(message)
        
        # Tamper with ciphertext
        tampered_ciphertext = bytearray(bundle.ciphertext)
        if len(tampered_ciphertext) > 0:
            tampered_ciphertext[0] ^= 0xFF  # Flip bits
        bundle_tampered = type('Bundle', (), {
            'encrypted_key': bundle.encrypted_key,
            'iv': bundle.iv,
            'ciphertext': bytes(tampered_ciphertext),
            'auth_tag': bundle.auth_tag,
            'sender_public_key': bundle.sender_public_key,
            'sender_id': bundle.sender_id
        })()
        
        # Receiver detects tampering
        receiver_manager = ExchangeManager(recipient_priv, sender_pub)
        with pytest.raises(ValueError):
            receiver_manager.secure_receive(bundle_tampered, recipient_priv)
    
    def test_multiple_messages(self):
        """Test sending multiple messages."""
        sender_priv, sender_pub = KeyPair.generate()
        recipient_priv, recipient_pub = KeyPair.generate()
        
        sender_manager = ExchangeManager(sender_priv, recipient_pub)
        receiver_manager = ExchangeManager(recipient_priv, sender_pub)
        
        messages = [
            "First message",
            "Second message",
            "Third message with special chars: ñ, é, ü"
        ]
        
        for msg_text in messages:
            # Send
            message = EmailMessage(msg_text)
            bundle = sender_manager.secure_send(message)
            
            # Receive
            decrypted = receiver_manager.secure_receive(bundle, recipient_priv)
            assert decrypted == msg_text, f"Message mismatch: {msg_text}"


class TestSchnorrSignature:
    """Test Schnorr signature functionality."""
    
    def test_sign_verify(self):
        """Test signature generation and verification."""
        signer = SchnorrSigner()
        private_key, public_key = KeyPair.generate()
        
        message = b"Test message for signing"
        signature = signer.generate_signature(message, private_key)
        
        assert signature is not None, "Signature should not be None"
        assert signature.get_r() is not None, "Signature should have 'r' component"
        assert signature.get_s() is not None, "Signature should have 's' component"
        
        # Verify signature
        is_valid = signer.verify_signature(message, signature, public_key)
        assert is_valid, "Signature verification should succeed"
    
    def test_signature_fails_on_modified_message(self):
        """Test that signature verification fails on modified message."""
        signer = SchnorrSigner()
        private_key, public_key = KeyPair.generate()
        
        message = b"Original message"
        signature = signer.generate_signature(message, private_key)
        
        # Modify message
        modified_message = b"Modified message"
        is_valid = signer.verify_signature(modified_message, signature, public_key)
        
        assert not is_valid, "Signature verification should fail on modified message"


class TestRC6GCM:
    """Test RC6-GCM encryption functionality."""
    
    def test_encrypt_decrypt(self):
        """Test RC6-GCM encryption and decryption."""
        import os
        key = os.urandom(32)
        iv = os.urandom(12)
        
        cipher = RC6GCM(key=key, iv=iv)
        plaintext = b"Test message for encryption"
        
        ciphertext, auth_tag = cipher.encrypt(plaintext, aad=b'')
        
        assert len(ciphertext) >= len(plaintext), "Ciphertext should be at least as long as plaintext"
        assert len(auth_tag) == 16, "Auth tag should be 16 bytes"
        
        # Decrypt
        decrypted = cipher.decrypt(ciphertext, auth_tag, aad=b'')
        assert decrypted == plaintext, "Decrypted message should match original"
    
    def test_decryption_fails_on_tampered_tag(self):
        """Test that tampering with auth tag is detected."""
        import os
        key = os.urandom(32)
        iv = os.urandom(12)
        
        cipher = RC6GCM(key=key, iv=iv)
        plaintext = b"Authentic message"
        
        ciphertext, auth_tag = cipher.encrypt(plaintext, aad=b'')
        
        # Tamper with auth tag
        tampered_tag = bytearray(auth_tag)
        tampered_tag[0] ^= 0xFF
        
        # Decryption should fail
        with pytest.raises(ValueError):
            cipher.decrypt(ciphertext, bytes(tampered_tag), aad=b'')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
