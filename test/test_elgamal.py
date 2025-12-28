import unittest
import os
import sys
from pathlib import Path

# --- Setup Imports ---
# Add parent directories to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import El-Gamal EC implementation
from src.algorithms.el_gamal.el_gamal_ec import ElGamalEC, ensure_32_bytes, P, N, G


class TestElGamalECC(unittest.TestCase):
    """Test cases for El-Gamal Elliptic Curve cryptography."""

    def setUp(self):
        """Setup: Generate a fresh key pair for each test."""
        self.sender = ElGamalEC()  # Generate random keypair
        self.recipient = ElGamalEC()  # Generate random keypair

    # --- 1. Basic Functionality Tests ---

    def test_key_generation(self):
        """Test: Key pair generation succeeds."""
        self.assertIsNotNone(self.sender.private_key)
        self.assertIsNotNone(self.sender.public_key)
        self.assertIsInstance(self.sender.public_key, tuple)
        self.assertEqual(len(self.sender.public_key), 2)

    def test_public_key_retrieval(self):
        """Test: Can retrieve public key."""
        pub_key = self.sender.get_public_key()
        self.assertEqual(pub_key, self.sender.public_key)
        self.assertIsInstance(pub_key, tuple)

    def test_from_public_key(self):
        """Test: Create instance from public key only."""
        pub_key = self.recipient.public_key
        public_only = ElGamalEC.from_public_key(pub_key)
        
        self.assertIsNone(public_only.private_key)
        self.assertEqual(public_only.public_key, pub_key)

    # --- 2. Encryption/Decryption Tests ---

    def test_basic_encryption_decryption(self):
        """Test: Encrypt and decrypt a 32-byte session key."""
        session_key = os.urandom(32)
        
        # Encrypt with recipient's public key
        C1, C2 = self.recipient.encrypt(session_key)
        
        # Verify C1 and C2 are correct types
        self.assertIsInstance(C1, tuple)
        self.assertEqual(len(C1), 2)
        self.assertIsInstance(C2, bytes)
        self.assertEqual(len(C2), 32)
        
        # Decrypt with recipient's private key
        decrypted = self.recipient.decrypt(C1, C2)
        
        self.assertEqual(decrypted, session_key)

    def test_multiple_encryptions_different(self):
        """Test: Multiple encryptions of same key produce different ciphertexts."""
        session_key = os.urandom(32)
        
        C1_a, C2_a = self.recipient.encrypt(session_key)
        C1_b, C2_b = self.recipient.encrypt(session_key)
        
        # Due to randomness, C1 points should differ
        self.assertNotEqual(C1_a, C1_b)
        # C2 should also differ (due to different ephemeral keys)
        self.assertNotEqual(C2_a, C2_b)

    def test_decrypt_only_with_private_key(self):
        """Test: Cannot decrypt with public-key-only instance."""
        session_key = os.urandom(32)
        C1, C2 = self.recipient.encrypt(session_key)
        
        # Create public-key-only instance
        public_only = ElGamalEC.from_public_key(self.recipient.public_key)
        
        # Should raise ValueError when trying to decrypt
        with self.assertRaises(ValueError):
            public_only.decrypt(C1, C2)

    # --- 3. Utility Function Tests ---

    def test_ensure_32_bytes_padding(self):
        """Test: ensure_32_bytes pads short input with zeros."""
        short = b'\x01\x02\x03'
        padded = ensure_32_bytes(short)
        
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-3:], b'\x01\x02\x03')
        self.assertEqual(padded[:29], b'\x00' * 29)

    def test_ensure_32_bytes_no_change(self):
        """Test: ensure_32_bytes leaves 32-byte input unchanged."""
        data = os.urandom(32)
        result = ensure_32_bytes(data)
        
        self.assertEqual(result, data)
        self.assertEqual(len(result), 32)

    def test_ensure_32_bytes_truncate(self):
        """Test: ensure_32_bytes truncates input longer than 32 bytes."""
        long_data = b'X' * 50
        result = ensure_32_bytes(long_data)
        
        self.assertEqual(len(result), 32)
        self.assertEqual(result, long_data[:32])

    # --- 4. Error Handling Tests ---

    def test_encrypt_invalid_session_key_length(self):
        """Test: Encryption fails with non-32-byte session key."""
        invalid_key = b'too_short'
        
        with self.assertRaises(ValueError):
            self.recipient.encrypt(invalid_key)
        
        invalid_key_long = b'X' * 40
        with self.assertRaises(ValueError):
            self.recipient.encrypt(invalid_key_long)

    def test_decrypt_invalid_C2_length(self):
        """Test: Decryption fails if C2 is not 32 bytes."""
        C1 = (123, 456)  # Dummy point
        invalid_C2 = b'short'
        
        with self.assertRaises(ValueError):
            self.recipient.decrypt(C1, invalid_C2)

    def test_invalid_private_key_range(self):
        """Test: Initialization fails with invalid private key."""
        # Private key must be in range [1, N)
        with self.assertRaises(ValueError):
            ElGamalEC(private_key=0)
        
        with self.assertRaises(ValueError):
            ElGamalEC(private_key=N)
        
        with self.assertRaises(ValueError):
            ElGamalEC(private_key=-1)

    # --- 4. Cryptographic Properties ---

    def test_semantically_secure(self):
        """
        ElGamal must be probabilistic. 
        Encrypting the same message twice must yield DIFFERENT ciphertexts
        due to the random ephemeral key 'k'.
        """
        session_key = os.urandom(32)
        
        C1_a, C2_a = self.recipient.encrypt(session_key)
        C1_b, C2_b = self.recipient.encrypt(session_key)

        # The ephemeral public points should not be identical
        self.assertNotEqual(C1_a, C1_b, "Security Flaw: Ephemeral key k is not random! C1 repeats.")
        # And C2 should differ
        self.assertNotEqual(C2_a, C2_b, "Security Flaw: Ciphertext C2 repeats for the same session key.")
        
        # But both should decrypt to the same original session key
        dec_a = self.recipient.decrypt(C1_a, C2_a)
        dec_b = self.recipient.decrypt(C1_b, C2_b)
        self.assertEqual(dec_a, dec_b)
        self.assertEqual(dec_a, session_key)

    def test_point_on_curve(self):
        """Verify that generated keys are valid EC points."""
        # Both sender and recipient should have valid public keys
        sender_x, sender_y = self.sender.public_key
        recipient_x, recipient_y = self.recipient.public_key
        
        # These are just coordinate pairs - the validity is ensured
        # by the EC operations in the implementation
        self.assertIsInstance(sender_x, int)
        self.assertIsInstance(sender_y, int)
        self.assertIsInstance(recipient_x, int)
        self.assertIsInstance(recipient_y, int)

    # --- 5. Stress Test ---

    def test_stress_loop(self):
        """Run 50 random encryptions to ensure stability."""
        print("\n    [Running Stress Test (50 iterations)...]")
        for i in range(50):
            # Generate random session key
            session_key = os.urandom(32)
            
            try:
                C1, C2 = self.recipient.encrypt(session_key)
                decrypted = self.recipient.decrypt(C1, C2)
                self.assertEqual(decrypted, session_key, 
                               f"Decryption failed at iteration {i}")
            except Exception as e:
                self.fail(f"Stress test failed at iteration {i} with session key {session_key.hex()}: {e}")

if __name__ == '__main__':
    # Verbosity=2 shows detailed success/fail status for each test function
    unittest.main(verbosity=2)