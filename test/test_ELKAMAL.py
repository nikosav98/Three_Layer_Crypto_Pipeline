import unittest
import os
import sys
from pathlib import Path

# --- Setup Imports ---
# Add parent directories to Python path to locate the original file and utils
# This assumes the test file is in the same directory or a 'tests' directory next to 'src'
sys.path.insert(0, str(Path(__file__).parent)) 
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import functions from your file (Ensure the filename matches your actual file)
try:
    from el_gamal_ec import generate_keys, encrypt, decrypt, ensure_32_bytes, P, A, B
except ImportError:
    print("Error: Could not import 'el_gamal_ec'. Check file name and path.")
    sys.exit(1)

class TestElGamalECC(unittest.TestCase):

    def setUp(self):
        """Runs before every test. Generates a fresh key pair."""
        self.priv_key, self.pub_key = generate_keys()

    # --- 1. Basic Functionality Tests ---

    def test_basic_encryption_decryption(self):
        """Test a simple 'Hello World' encryption cycle."""
        message = "Hello World"
        ciphertext = encrypt(self.pub_key, message)
        decrypted = decrypt(self.priv_key, ciphertext)
        self.assertEqual(decrypted.decode('utf-8'), message)

    def test_short_string(self):
        """Test with a very short string."""
        message = "Hi"
        ciphertext = encrypt(self.pub_key, message)
        decrypted = decrypt(self.priv_key, ciphertext)
        self.assertEqual(decrypted.decode('utf-8'), message)

    def test_empty_string(self):
        """Test with an empty string."""
        # This checks if the mapping logic handles empty input (usually maps to 0)
        message = "" 
        ciphertext = encrypt(self.pub_key, message)
        decrypted = decrypt(self.priv_key, ciphertext)
        self.assertEqual(decrypted.decode('utf-8'), message)

    # --- 2. Advanced Data Types Tests ---

    def test_utf8_support(self):
        """Test with non-ASCII characters (e.g., Hebrew)."""
        message = "שלום" # Contains multi-byte characters
        ciphertext = encrypt(self.pub_key, message)
        decrypted = decrypt(self.priv_key, ciphertext)
        self.assertEqual(decrypted.decode('utf-8'), message)

    def test_bytes_input(self):
        """Test passing raw bytes directly instead of a string."""
        message_bytes = b'\xde\xad\xbe\xef'
        ciphertext = encrypt(self.pub_key, message_bytes)
        decrypted = decrypt(self.priv_key, ciphertext)
        self.assertEqual(decrypted, message_bytes)

    # --- 3. Edge Cases & Limits ---

    def test_max_length_boundary(self):
        """Test exactly 31 bytes (the hard limit in your code)."""
        message = "A" * 31
        ciphertext = encrypt(self.pub_key, message)
        decrypted = decrypt(self.priv_key, ciphertext)
        self.assertEqual(decrypted.decode('utf-8'), message)

    def test_overflow_truncation(self):
        """Test providing more than 31 bytes (expected to be truncated)."""
        message = "B" * 40 # 40 bytes
        expected = "B" * 31 # Code logic truncates to 31
        
        ciphertext = encrypt(self.pub_key, message)
        decrypted = decrypt(self.priv_key, ciphertext)
        
        self.assertEqual(decrypted.decode('utf-8'), expected)
        self.assertNotEqual(decrypted.decode('utf-8'), message)

    # --- 4. Cryptographic Properties ---

    def test_semantically_secure(self):
        """
        ElGamal must be probabilistic. 
        Encrypting the same message twice must yield DIFFERENT ciphertexts
        due to the random ephemeral key 'k'.
        """
        msg = "Secret"
        c1_a, c2_a = encrypt(self.pub_key, msg)
        c1_b, c2_b = encrypt(self.pub_key, msg)

        # The points (tuples) should not be identical
        self.assertNotEqual(c1_a, c1_b, "Security Flaw: Ephemeral key k is not random! C1 repeats.")
        self.assertNotEqual(c2_a, c2_b, "Security Flaw: Ciphertext C2 repeats for the same message.")
        
        # But both should decrypt to the same original message
        dec_a = decrypt(self.priv_key, (c1_a, c2_a))
        dec_b = decrypt(self.priv_key, (c1_b, c2_b))
        self.assertEqual(dec_a, dec_b)

    def test_public_key_validity(self):
        """Verify that the generated public key lies on the curve."""
        x, y = self.pub_key
        # Curve Equation: y^2 = x^3 + ax + b (mod p)
        lhs = (y * y) % P
        rhs = (pow(x, 3, P) + (A * x) + B) % P
        self.assertEqual(lhs, rhs, "Public key is not a valid point on the curve")

    # --- 5. Stress Test ---

    def test_stress_loop(self):
        """Run 50 random encryptions to ensure stability in Koblitz mapping."""
        print("\n    [Running Stress Test (50 iterations)...]")
        for i in range(50):
            # Generate random message of random length (1-30 bytes)
            rand_len = 1 + (os.urandom(1)[0] % 30)
            msg_bytes = os.urandom(rand_len)
            
            try:
                ciphertext = encrypt(self.pub_key, msg_bytes)
                decrypted = decrypt(self.priv_key, ciphertext)
                self.assertEqual(decrypted, msg_bytes)
            except Exception as e:
                self.fail(f"Stress test failed at iteration {i} with message {msg_bytes.hex()}: {e}")

if __name__ == '__main__':
    # Verbosity=2 shows detailed success/fail status for each test function
    unittest.main(verbosity=2)