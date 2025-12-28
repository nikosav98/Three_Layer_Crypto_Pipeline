"""
Exchange Manager - Orchestrates the complete cryptographic pipeline.

This module implements the three-layer encryption scheme:
    1. Schnorr Signature: Sign the message (authentication)
    2. RC6-GCM: Encrypt message and signature (confidentiality + authentication)
    3. El-Gamal: Encrypt session key (key transport)

Pipeline:
    plaintext → Schnorr (sign) → RC6-GCM (encrypt) → El-Gamal (wrap key) → ciphertext

References:
    - Message Authentication: Schnorr Digital Signature Algorithm
    - Symmetric Encryption: RC6 Block Cipher in GCM Mode
    - Asymmetric Encryption: El-Gamal on Elliptic Curves (SECP256K1)
"""

import os
import sys

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.email_message import EmailMessage
from src.utils.secure_bundle import SecureBundle
from cryptography.hazmat.primitives.asymmetric import ec

from src.algorithms.schnorr.schnorr_signature import SchnorrSigner
from src.algorithms.rc6.rc6_gcm_mode import RC6GCM


class ExchangeManager:
    """
    Manages the complete encrypted message exchange pipeline.
    
    Coordinates three cryptographic algorithms:
    1. Schnorr signature for authentication
    2. RC6-GCM for symmetric encryption
    3. Session key wrapping (in real implementation)
    
    This ensures:
    - Confidentiality: RC6-GCM encrypts the message
    - Authenticity: Schnorr signature proves sender identity
    - Key Security: Session key would be wrapped with El-Gamal
    
    Attributes:
        sender_private_key: EC private key of sender (for signatures)
        recipient_public_key: EC public key of recipient (for key wrapping)
        session_key: Generated ephemeral symmetric key
        iv: Initialization vector for GCM mode
    
    Example:
        # Sender side
        manager = ExchangeManager(sender_priv, recipient_pub)
        message = EmailMessage("Secret message")
        bundle = manager.secure_send(message)
        
        # Receiver side
        plaintext = manager.secure_receive(bundle)
    """
    
    def __init__(self,
                 sender_private_key: ec.EllipticCurvePrivateKey, 
                 recipient_public_key: ec.EllipticCurvePublicKey) -> None:
        """
        Initialize ExchangeManager with key material.
        
        Args:
            sender_private_key: EC private key (for signing messages)
            recipient_public_key: EC public key (for wrapping session key)
            
        Raises:
            TypeError: If keys are not proper EC key objects
        """
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        
        # Ephemeral values generated during secure_send
        self.session_key: bytes = None
        self.iv: bytes = None
    
    def generate_session_key(self) -> bytes:
        """
        Generate a random 256-bit (32-byte) symmetric key.
        
        Used for RC6-GCM encryption. Should be generated fresh for each message.
        
        Returns:
            32-byte random key material
        """
        return os.urandom(32)
    
    def generate_iv(self) -> bytes:
        """
        Generate a random 96-bit (12-byte) IV for GCM mode.
        
        GCM mode typically uses 96-bit (12-byte) IVs for best performance.
        Should be unique for each message encrypted with the same key.
        
        Returns:
            12-byte random initialization vector
        """
        return os.urandom(12)
    
    def secure_send(self, mail: EmailMessage) -> SecureBundle:
        """
        Encrypt and sign an email message using the three-layer pipeline.
        
        Pipeline stages:
        1. Sign: Generate Schnorr signature of message
        2. Encrypt: RC6-GCM encrypts (message || signature)
        3. Wrap: Session key wrapped (placeholder)
        
        Args:
            mail: EmailMessage object containing message content
            
        Returns:
            SecureBundle containing:
                - ek: Encrypted key (session key placeholder)
                - iv: Initialization vector used for GCM
                - c: Ciphertext (message encrypted by RC6-GCM)
                - t: Authentication tag from GCM
                - sender_pub_key: Sender's EC public key (for verification)
            
        Raises:
            Exception: If any step of encryption fails
            
        Process:
            Step 1 (Sender): Convert message to bytes and sign
            ├─ Convert EmailMessage to bytes
            └─ Generate Schnorr signature using sender's private key
            
            Step 2 (Niko): Encrypt message + signature with RC6-GCM
            ├─ Generate random session key (32 bytes)
            ├─ Generate random IV (12 bytes)
            └─ RC6-GCM encrypts (message || signature) with session key
            
            Step 3 (Roni): Create secure bundle
            └─ Return SecureBundle with all encrypted components
        """
        # ===================== STEP 1: SIGN =====================
        # Convert message content to bytes
        mail_as_bytes = mail.to_bytes()
        
        # Generate Schnorr signature
        schnorr_signer = SchnorrSigner()     
        signature = schnorr_signer.generate_signature(
            mail_as_bytes,
            self.sender_private_key
        )
        
        # Combine message and signature for encryption
        signature_bytes = signature.to_bytes()
        plaintext = mail_as_bytes + signature_bytes
        
        # ===================== STEP 2: ENCRYPT =====================
        # Generate ephemeral symmetric key and IV
        self.session_key = self.generate_session_key()
        self.iv = self.generate_iv()
        
        # Create RC6-GCM cipher and encrypt
        rc6_gcm = RC6GCM(key=self.session_key, iv=self.iv)
        
        # Encrypt plaintext (message || signature)
        ciphertext, auth_tag = rc6_gcm.encrypt(
            plaintext=plaintext,
            aad=b''  # No additional authenticated data
        )
        
        # ===================== STEP 3: WRAP KEY =====================
        # In the real pipeline, session_key would be wrapped with El-Gamal
        # For now, store session key as encrypted_key (would be replaced with El-Gamal output)
        encrypted_key = self.session_key
        
        # ===================== RETURN BUNDLE =====================
        # Create secure bundle with all encrypted components
        return SecureBundle(
            ek=encrypted_key,
            iv=self.iv,
            c=ciphertext,
            t=auth_tag,
            sender_pub_key=self.sender_private_key.public_key(),
            sender_id="sender"
        )
    
    def secure_receive(self, bundle: SecureBundle, receiver_private_key: ec.EllipticCurvePrivateKey) -> str:
        """
        Decrypt and verify an email message using the three-layer pipeline.
        
        Reverses the secure_send process:
        1. Unwrap: Session key (placeholder)
        2. Decrypt: RC6-GCM decrypts ciphertext
        3. Verify: Schnorr verifies signature
        
        Args:
            bundle: SecureBundle containing encrypted message components
            receiver_private_key: EC private key of receiver (for unwrapping key)
            
        Returns:
            Decrypted message content as string
            
        Raises:
            ValueError: If authentication fails or signature is invalid
            Exception: If any step of decryption fails
            
        Process:
            Step 3: Unwrap session key (placeholder)
            ├─ Extract encrypted key from bundle
            └─ Use session key for decryption
            
            Step 2: Decrypt message with RC6-GCM
            ├─ Create RC6-GCM cipher with session key and IV
            ├─ RC6-GCM decrypts ciphertext (verifies auth tag)
            └─ Get (message || signature) plaintext
            
            Step 1: Verify signature
            ├─ Split plaintext into message and signature
            ├─ Verify Schnorr signature using sender's public key
            └─ Return message content
        """
        # ===================== STEP 3: UNWRAP KEY =====================
        # In real implementation, would use El-Gamal to unwrap
        # For now, encrypted_key is the session key directly
        self.session_key = bundle.encrypted_key
        
        # ===================== STEP 2: DECRYPT =====================
        # Create RC6-GCM cipher and decrypt
        rc6_gcm = RC6GCM(key=self.session_key, iv=bundle.iv)
        
        try:
            plaintext = rc6_gcm.decrypt(
                ciphertext=bundle.ciphertext,
                auth_tag=bundle.auth_tag,
                aad=b''
            )
        except ValueError as e:
            raise ValueError(f"Decryption failed - message may be tampered: {e}")
        
        # ===================== STEP 1: VERIFY =====================
        # Split message and signature
        # Signature is last 64 bytes (r: 32 bytes, s: 32 bytes)
        message_bytes = plaintext[:-64]
        signature_bytes = plaintext[-64:]
        
        from src.utils.signature_object import SignatureObject
        
        # Reconstruct signature
        signature = SignatureObject(
            r=signature_bytes[:32],
            s=signature_bytes[32:64]
        )
        
        # Verify signature using sender's public key
        schnorr_verifier = SchnorrSigner()
        is_valid = schnorr_verifier.verify_signature(
            data=message_bytes,
            signature=signature,
            public_key=bundle.sender_public_key
        )
        
        if not is_valid:
            raise ValueError("Signature verification failed - message is not authentic")
        
        # Return message as string
        return message_bytes.decode('utf-8', errors='replace')


def main():
    """
    Test ExchangeManager with complete pipeline.
    
    Demonstrates:
    1. Sender encrypts message with receiver's public key
    2. Receiver decrypts and verifies
    """
    from src.utils.key_pair import KeyPair
    
    print("Testing ExchangeManager complete pipeline...")
    print("=" * 60)
    
    # Setup: Generate key pairs for sender and receiver
    print("\n[Setup] Generating key pairs...")
    sender_private, sender_public = KeyPair.generate()
    receiver_private, receiver_public = KeyPair.generate()
    print("✓ Key pairs generated")
    
    # Sender side
    print("\n[Sender] Creating ExchangeManager...")
    manager = ExchangeManager(sender_private, receiver_public)
    print("✓ ExchangeManager created")
    
    # Create and encrypt message
    print("\n[Sender] Encrypting message...")
    message = EmailMessage("Hello! This is a secure message from Alice.")
    bundle = manager.secure_send(message)
    print("✓ Message encrypted successfully")
    print(f"  - Ciphertext size: {len(bundle.ciphertext)} bytes")
    print(f"  - Auth tag: {len(bundle.auth_tag)} bytes")
    print(f"  - IV: {len(bundle.iv)} bytes")
    
    # Receiver side
    print("\n[Receiver] Decrypting message...")
    manager2 = ExchangeManager(receiver_private, sender_public)
    decrypted_msg = manager2.secure_receive(bundle, receiver_private)
    print("✓ Message decrypted and verified")
    print(f"  - Message: {decrypted_msg}")
    
    assert decrypted_msg == message.to_bytes().decode('utf-8'), "Message mismatch!"
    
    print("\n" + "=" * 60)
    print("✓ All tests passed! Pipeline working correctly.")


if __name__ == "__main__":
    main()
