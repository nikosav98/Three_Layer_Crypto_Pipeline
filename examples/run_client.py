"""
Example: Secure client connecting to server.

This example shows how to:
1. Create a secure client
2. Connect to the server
3. Perform key exchange
4. Send encrypted messages

Usage:
    python examples/run_client.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.client import SecureClient
from src.algorithms.key_exchange.exchange_manager import ExchangeManager
from src.utils.email_message import EmailMessage
from src.utils.key_pair import KeyPair
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Run secure client example."""
    print("=" * 60)
    print("Secure Client - Cryptography Course Project")
    print("=" * 60)
    
    # Create client
    client = SecureClient(host='localhost', port=5000, client_id='user_alice')
    
    print(f"\nConnecting to server at localhost:5000...")
    
    if not client.connect():
        logger.error("Failed to connect to server")
        return
    
    logger.info("Connected to server successfully!")
    
    # Example: Prepare and send encrypted message
    try:
        # Generate sender/receiver key pairs
        sender_keys = KeyPair.generate()
        recipient_keys = KeyPair.generate()
        
        # Create exchange manager
        manager = ExchangeManager(
            sender_private_key=sender_keys[0],
            recipient_public_key=recipient_keys[1]
        )
        
        # Create a message
        message = EmailMessage("Hello from secure client!")
        
        logger.info("Message prepared, ready to send to server")
        
        # In a real scenario, you would:
        # 1. Use ExchangeManager to prepare secure bundle
        # 2. Extract encrypted_key, iv, ciphertext, auth_tag
        # 3. Send using client.send_secure_message()
        
        # For this example, we send dummy encrypted data
        dummy_encrypted_key = b'0' * 64
        dummy_iv = b'0' * 12
        dummy_ciphertext = b'0' * 100
        dummy_tag = b'0' * 16
        
        logger.info("Sending test encrypted message to server...")
        client.send_secure_message(
            dummy_encrypted_key,
            dummy_iv,
            dummy_ciphertext,
            dummy_tag
        )
        
    except Exception as e:
        logger.error(f"Error preparing message: {e}")
    finally:
        # Disconnect
        client.disconnect()
        logger.info("Client disconnected")


if __name__ == "__main__":
    main()
