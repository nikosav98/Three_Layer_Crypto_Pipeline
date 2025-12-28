"""
RC6 in GCM (Galois/Counter Mode) Implementation.

GCM provides both encryption and authentication in one operation.
This is an authenticated encryption mode that prevents tampering.

The mode works by:
1. Using RC6 as the block cipher in counter mode (CTR) for encryption
2. Using Galois field multiplication for authentication
3. Producing both ciphertext and authentication tag

References:
    - NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
"""

import struct
from typing import Tuple

try:
    from src.algorithms.rc6.rc6 import expand_key, encrypt_block
except ImportError:
    from algorithms.rc6.rc6 import expand_key, encrypt_block


class GHASH:
    """
    Galois/Counter Mode Hash (GHASH) for authentication.
    
    This implements the GHASH function which authenticates data
    using Galois field arithmetic.
    """
    
    @staticmethod
    def gf_mult(x: int, y: int, h: int = 0xE1) -> int:
        """
        Multiply two 128-bit numbers in GF(2^128).
        
        Args:
            x: First 128-bit number
            y: Second 128-bit number
            h: Reduction polynomial (default for GCM)
            
        Returns:
            Product in GF(2^128)
        """
        z = 0
        v = y
        
        for i in range(128):
            if (x >> (127 - i)) & 1:
                z ^= v
            
            # Shift v left by 1 bit in GF(2^128)
            lsb = v & 1
            v >>= 1
            if lsb:
                v ^= (h << 120)
        
        return z & ((1 << 128) - 1)
    
    @staticmethod
    def bytes_to_int(data: bytes) -> int:
        """Convert bytes to 128-bit integer."""
        if len(data) < 16:
            data = data + b'\x00' * (16 - len(data))
        return int.from_bytes(data[:16], 'big')
    
    @staticmethod
    def int_to_bytes(value: int) -> bytes:
        """Convert 128-bit integer to bytes."""
        return value.to_bytes(16, 'big')
    
    @classmethod
    def compute(cls, h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        """
        Compute GHASH tag.
        
        Args:
            h: Hash key (output of E(K, 0^128))
            aad: Additional Authenticated Data
            ciphertext: The ciphertext to authenticate
            
        Returns:
            128-bit authentication tag
        """
        h_int = cls.bytes_to_int(h)
        
        # Pad AAD to 128-bit boundary
        aad_padded = aad + b'\x00' * ((16 - len(aad) % 16) % 16)
        
        # Pad ciphertext to 128-bit boundary
        ct_padded = ciphertext + b'\x00' * ((16 - len(ciphertext) % 16) % 16)
        
        # Process AAD and ciphertext
        ghash_input = aad_padded + ct_padded
        ghash_input += struct.pack('>QQ', len(aad) * 8, len(ciphertext) * 8)
        
        tag = 0
        for i in range(0, len(ghash_input), 16):
            block = ghash_input[i:i+16]
            block_int = cls.bytes_to_int(block)
            tag = cls.gf_mult(tag ^ block_int, h_int)
        
        return cls.int_to_bytes(tag)


class RC6GCM:
    """
    RC6 cipher in GCM (Galois/Counter Mode).
    
    Provides authenticated encryption: encrypts data and produces an
    authentication tag to detect tampering.
    
    Attributes:
        key: Encryption key (16, 24, or 32 bytes)
        iv: Initialization vector (nonce) - typically 96 bits (12 bytes)
    
    Example:
        cipher = RC6GCM(key=os.urandom(32), iv=os.urandom(12))
        ciphertext, tag = cipher.encrypt(plaintext, aad=b'')
        plaintext = cipher.decrypt(ciphertext, tag, aad=b'')
    """
    
    def __init__(self, key: bytes, iv: bytes):
        """
        Initialize RC6-GCM.
        
        Args:
            key: Encryption key (16, 24, or 32 bytes)
            iv: Initialization vector / nonce (typically 12 bytes for GCM)
            
        Raises:
            ValueError: If key or IV size is invalid
        """
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
        
        self.key = key
        self.iv = iv
        self.S = expand_key(key)
    
    def _generate_hash_key(self) -> bytes:
        """
        Generate hash key H = E(K, 0^128).
        
        Returns:
            128-bit hash key
        """
        zero_block = b'\x00' * 16
        return encrypt_block(zero_block, self.S)
    
    def _generate_counter_blocks(self, length: int) -> list[bytes]:
        """
        Generate counter mode blocks for encryption.
        
        Args:
            length: Number of blocks needed
            
        Returns:
            List of counter blocks
        """
        blocks = []
        
        # Build initial counter: IV || 0^31 1
        if len(self.iv) == 12:
            counter = int.from_bytes(self.iv, 'big')
            counter = (counter << 32) | 1
        else:
            # If IV is not 12 bytes, hash it
            h = self._generate_hash_key()
            ghash_tag = GHASH.compute(h, b'', self.iv)
            counter = int.from_bytes(ghash_tag, 'big') | 1
        
        # Generate counter blocks
        for i in range(length):
            counter_bytes = ((counter + i) % (2**128)).to_bytes(16, 'big')
            blocks.append(counter_bytes)
        
        return blocks
    
    def encrypt(self, plaintext: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext and generate authentication tag.
        
        Args:
            plaintext: Data to encrypt
            aad: Additional Authenticated Data (not encrypted, but authenticated)
            
        Returns:
            Tuple of (ciphertext, authentication_tag)
            
        Process:
            1. Generate hash key H
            2. Generate counter blocks for CTR mode
            3. Encrypt plaintext using CTR mode
            4. Compute GHASH authentication tag
        """
        h = self._generate_hash_key()
        
        # Generate counter blocks
        num_blocks = (len(plaintext) + 15) // 16
        counter_blocks = self._generate_counter_blocks(num_blocks + 1)
        
        # Encrypt plaintext using CTR mode
        ciphertext = b''
        for i, block in enumerate(counter_blocks[1:num_blocks + 1]):
            encrypted_block = encrypt_block(block, self.S)
            
            start = i * 16
            end = min(start + 16, len(plaintext))
            plaintext_block = plaintext[start:end]
            
            # XOR with keystream
            cipher_block = bytes(a ^ b for a, b in zip(plaintext_block, encrypted_block[:len(plaintext_block)]))
            ciphertext += cipher_block
        
        # Compute authentication tag
        tag = GHASH.compute(h, aad, ciphertext)
        
        # XOR with E(K, counter_0) for final tag
        counter_0_encrypted = encrypt_block(counter_blocks[0], self.S)
        auth_tag = bytes(a ^ b for a, b in zip(tag, counter_0_encrypted))
        
        return ciphertext, auth_tag
    
    def decrypt(self, ciphertext: bytes, auth_tag: bytes, aad: bytes = b'') -> bytes:
        """
        Decrypt ciphertext and verify authentication tag.
        
        Args:
            ciphertext: Data to decrypt
            auth_tag: Authentication tag to verify
            aad: Additional Authenticated Data (same as during encryption)
            
        Returns:
            Plaintext if tag is valid
            
        Raises:
            ValueError: If authentication tag is invalid
            
        Process:
            1. Generate hash key H
            2. Verify authentication tag using GHASH
            3. Decrypt ciphertext using CTR mode
        """
        h = self._generate_hash_key()
        
        # Verify authentication tag
        computed_tag_with_counter = GHASH.compute(h, aad, ciphertext)
        
        # Generate counter blocks
        num_blocks = (len(ciphertext) + 15) // 16
        counter_blocks = self._generate_counter_blocks(num_blocks + 1)
        
        # XOR with E(K, counter_0) for tag verification
        counter_0_encrypted = encrypt_block(counter_blocks[0], self.S)
        computed_tag = bytes(a ^ b for a, b in zip(computed_tag_with_counter, counter_0_encrypted))
        
        # Constant-time comparison to prevent timing attacks
        if not self._constant_time_compare(computed_tag, auth_tag):
            raise ValueError("Authentication tag verification failed - data may be tampered")
        
        # Decrypt using CTR mode
        plaintext = b''
        for i, block in enumerate(counter_blocks[1:num_blocks + 1]):
            encrypted_block = encrypt_block(block, self.S)
            
            start = i * 16
            end = min(start + 16, len(ciphertext))
            ciphertext_block = ciphertext[start:end]
            
            # XOR with keystream
            plain_block = bytes(a ^ b for a, b in zip(ciphertext_block, encrypted_block[:len(ciphertext_block)]))
            plaintext += plain_block
        
        return plaintext
    
    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        
        Prevents timing attacks by always comparing all bytes
        regardless of where mismatch occurs.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0


def main():
    """Test RC6-GCM implementation."""
    import os
    
    print("Testing RC6-GCM mode...")
    
    # Test vectors
    key = os.urandom(32)
    iv = os.urandom(12)
    plaintext = b"Hello, World! This is a test message."
    aad = b"Additional Authenticated Data"
    
    cipher = RC6GCM(key, iv)
    
    # Encrypt
    ciphertext, auth_tag = cipher.encrypt(plaintext, aad)
    print(f"✓ Encryption successful")
    print(f"  Plaintext: {len(plaintext)} bytes")
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"  Auth Tag: {len(auth_tag)} bytes")
    
    # Decrypt
    decrypted = cipher.decrypt(ciphertext, auth_tag, aad)
    assert decrypted == plaintext, "Decryption failed!"
    print(f"✓ Decryption successful and matches plaintext")
    
    # Test tampering detection
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip bits in first byte
    
    try:
        cipher.decrypt(bytes(tampered_ciphertext), auth_tag, aad)
        print("✗ Tampering detection failed!")
    except ValueError as e:
        print(f"✓ Tampering detected: {e}")
    
    print("\nAll tests passed!")


if __name__ == "__main__":
    main()



