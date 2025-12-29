"""
El-Gamal Elliptic Curve Key Encapsulation (KEM).

El-Gamal on elliptic curves provides public-key encryption.
This implementation uses SECP256K1 curve for key wrapping.

The algorithm works as follows:
1. Server publishes public key point (an EC point)
2. Client generates ephemeral key pair
3. Client computes shared secret using Diffie-Hellman
4. Client encrypts session key with shared secret
5. Server decrypts using their private key

References:
    - Handbook of Elliptic and Hyperelliptic Curve Cryptography
    - SEC 2: Recommended Elliptic Curve Domain Parameters
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from src.utils.utils import ec_scalar_mult, ec_point_add
except ImportError:
    from utils.utils import ec_scalar_mult, ec_point_add

# SECP256K1 Parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def ensure_32_bytes(data: bytes) -> bytes:
    """
    Ensure byte array is exactly 32 bytes.
    
    Pads with leading zeros if needed, or truncates if too long.
    
    Args:
        data: Input bytes to normalize
        
    Returns:
        32-byte array
    """
    if len(data) < 32:
        return b'\x00' * (32 - len(data)) + data
    elif len(data) > 32:
        return data[:32]
    return data


class ElGamalEC:
    """
    El-Gamal Elliptic Curve public-key encryption.
    
    This class provides key encapsulation for wrapping session keys.
    Each instance represents one side of the key exchange.
    
    Attributes:
        private_key: Secret scalar (for decryption)
        public_key: Public EC point (for encryption)
    """
    
    def __init__(self, private_key: int = None):
        """
        Initialize El-Gamal with a private key.
        
        Args:
            private_key: Secret scalar value. If None, generates random.
            
        Raises:
            ValueError: If private_key is outside valid range (1, N)
        """
        if private_key is None:
            # Generate random private key
            self.private_key = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
        else:
            if not (1 <= private_key < N):
                raise ValueError(f"Private key must be in range [1, {N})")
            self.private_key = private_key
        
        # Compute public key: P = d * G
        self.public_key = ec_scalar_mult(self.private_key, G, P)
        
        if self.public_key is None:
            raise ValueError("Failed to compute public key")
    
    @staticmethod
    def from_public_key(public_key: tuple) -> 'ElGamalEC':
        """
        Create El-Gamal instance from public key only.
        
        Useful when you only need to encrypt (no private key available).
        
        Args:
            public_key: Tuple of (x, y) coordinates of public key point
            
        Returns:
            ElGamalEC instance with public_key set, private_key=None
        """
        instance = object.__new__(ElGamalEC)
        instance.private_key = None
        instance.public_key = public_key
        return instance
    
    def get_public_key(self) -> tuple:
        """
        Get the public key as EC point coordinates.
        
        Returns:
            Tuple of (x, y) coordinates
        """
        return self.public_key
    
    def encrypt(self, session_key: bytes) -> tuple:
        """
        Encrypt a session key using El-Gamal.
        
        This creates a key encapsulation: outputs ciphertext that contains
        the encrypted session key. The ciphertext is a pair of EC points.
        
        Args:
            session_key: 256-bit (32-byte) symmetric key to encrypt
            
        Returns:
            Tuple of (C1, C2) where:
                C1 = r * G (ephemeral public key)
                C2 = session_key XOR (r * public_key)
        
        Raises:
            ValueError: If session_key is not 32 bytes
            
        Process:
            1. Generate ephemeral random scalar r
            2. Compute C1 = r * G (ephemeral public point)
            3. Compute shared secret = r * recipient_public_key
            4. Derive symmetric key from shared secret
            5. XOR session_key with derived key for C2
            6. Return (C1, C2) as encrypted bundle
        """
        if len(session_key) != 32:
            raise ValueError(f"Session key must be 32 bytes, got {len(session_key)}")
        
        # Generate ephemeral key
        r = int.from_bytes(os.urandom(32), 'big') % (N - 1) + 1
        
        # C1 = r * G (ephemeral public point)
        C1 = ec_scalar_mult(r, G, P)
        if C1 is None:
            raise ValueError("Failed to compute ephemeral public point")
        
        # Compute shared secret: r * recipient_public_key
        shared_secret = ec_scalar_mult(r, self.public_key, P)
        if shared_secret is None:
            raise ValueError("Failed to compute shared secret")
        
        # Derive symmetric key from shared secret x-coordinate
        # Use SHA-256 for KDF
        import hashlib
        x_coord = shared_secret[0].to_bytes(32, 'big')
        derived_key = hashlib.sha256(x_coord).digest()
        
        # C2 = session_key XOR derived_key
        C2 = bytes(a ^ b for a, b in zip(session_key, derived_key))
        
        # Return C1 as point (x, y) and C2 as bytes
        return (C1, C2)
    
    def decrypt(self, C1: tuple, C2: bytes) -> bytes:
        """
        Decrypt a session key using El-Gamal.
        
        Args:
            C1: Ephemeral public point (x, y) from encryption
            C2: Encrypted symmetric key bytes
            
        Returns:
            Decrypted session key (32 bytes)
            
        Raises:
            ValueError: If private_key is not available or decryption fails
            
        Process:
            1. Check that private key is available
            2. Compute shared secret = private_key * C1
            3. Derive symmetric key from shared secret
            4. XOR C2 with derived key to recover session_key
        """
        if self.private_key is None:
            raise ValueError("Cannot decrypt without private key")
        
        if len(C2) != 32:
            raise ValueError(f"Encrypted key must be 32 bytes, got {len(C2)}")
        
        # Compute shared secret: private_key * C1
        shared_secret = ec_scalar_mult(self.private_key, C1, P)
        if shared_secret is None:
            raise ValueError("Failed to compute shared secret during decryption")
        
        # Derive symmetric key using same method as encryption
        import hashlib
        x_coord = shared_secret[0].to_bytes(32, 'big')
        derived_key = hashlib.sha256(x_coord).digest()
        
        # Recover session_key: C2 XOR derived_key
        session_key = bytes(a ^ b for a, b in zip(C2, derived_key))
        
        return session_key
    
    @staticmethod
    def point_to_bytes(point: tuple) -> bytes:
        """
        Serialize EC point to bytes (compressed format).
        
        Args:
            point: Tuple of (x, y) coordinates
            
        Returns:
            33-byte compressed point format
        """
        x, y = point
        x_bytes = x.to_bytes(32, 'big')
        # First byte indicates if y is even (0x02) or odd (0x03)
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x_bytes
    
    @staticmethod
    def bytes_to_point(data: bytes) -> tuple:
        """
        Deserialize bytes to EC point.
        
        Args:
            data: 33-byte compressed point format
            
        Returns:
            Tuple of (x, y) coordinates
            
        Raises:
            ValueError: If point is not on the curve
        """
        if len(data) != 33:
            raise ValueError(f"Compressed point must be 33 bytes, got {len(data)}")
        
        prefix = data[0]
        x = int.from_bytes(data[1:], 'big')
        
        # Recover y from x using curve equation: y^2 = x^3 + 7
        y_squared = (pow(x, 3, P) + 7) % P
        y = pow(y_squared, (P + 1) // 4, P)
        
        # Check if we got the right y (the one that matches prefix)
        if (y % 2 == 0) != (prefix == 0x02):
            y = P - y
        
        # Verify point is on curve
        if (y * y) % P != y_squared:
            raise ValueError("Point is not on the curve")
        
        return (x, y)
