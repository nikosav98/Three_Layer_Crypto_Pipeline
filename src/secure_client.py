"""
Secure Client Application - Encrypts and sends messages to server.

This client implements the complete cryptographic pipeline:
1. Generates/loads key pair (SECP256K1)
2. Creates email message
3. Uses ExchangeManager to encrypt message with three-layer pipeline:
   - Schnorr signature for authentication
   - RC6-GCM for confidentiality
   - El-Gamal for key wrapping
4. Sends encrypted bundle to server over TCP
5. Receives and displays server response

Protocol:
    1. CONNECT to server (0.0.0.0:5000)
    2. SEND encrypted message as SecureBundle (JSON + Base64)
    3. RECEIVE ACK/response from server
    4. CLOSE connection

Usage:
    python src/secure_client.py
    
    Enter message when prompted. Client will encrypt using server's
    public key and send the encrypted bundle.
    
References:
    - Message Format: SecureBundle (encrypted_key, iv, ciphertext, auth_tag, sender_pub_key)
    - Encryption: Schnorr + RC6-GCM + El-Gamal (complete 3-layer pipeline)
    - Transport: TCP socket with JSON serialization
"""

import socket
import json
import base64
import os
import sys
from typing import Optional, Tuple

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.key_pair import KeyPair
from src.utils.email_message import EmailMessage
from src.algorithms.key_exchange.exchange_manager import ExchangeManager
from src.utils.input_validation import get_network_config, validate_ip_address, validate_port
from cryptography.hazmat.primitives import serialization

class SecureClient:
    """
    Secure client for encrypted message transmission.
    
    Handles:
    - Key pair management (SECP256K1)
    - Message encryption with ExchangeManager
    - Secure communication with server
    - Response handling
    
    Attributes:
        host: Server IP address
        port: Server port number
        client_private_key: Client's EC private key
        client_public_key: Client's EC public key
        server_public_key: Server's EC public key (for encryption)
        socket: TCP socket connection
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, 
                 server_public_key_coords: Optional[Tuple[int, int]] = None) -> None:
        """
        Initialize secure client.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
            server_public_key_coords: Server's public key (x, y) coordinates
                                     If None, will attempt to receive from server
        
        Raises:
            Exception: If key generation fails
        """
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        
        # Generate client's key pair
        print("[Client] Generating key pair...")
        
        # 1. Generate the keys
        self.client_private_key, self.client_public_key = KeyPair.generate()

        # 2. Serialize Private Key to PEM format
        private_pem = self.client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # 3. Serialize Public Key to PEM format
        public_pem = self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # 4. Print the keys correctly
        print("Key pair generated:")
        print(f"Client private key:\n{private_pem}")
        print(f"Client public key:\n{public_pem}")
        
        
        # Store server's public key (needed for encryption)
        self.server_public_key = server_public_key_coords
        self.socket = None
    
    def connect(self) -> bool:
        """
        Establish TCP connection to server.
        
        Returns:
            True if connection successful, False otherwise
            
        Raises:
            socket.error: If connection fails
        """
        try:
            print(f"\n[Client] Connecting to server {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print("Connected to server")
            return True
        except socket.error as e:
            print(f"Connection failed: {e}")
            return False
    
    def exchange_keys(self) -> bool:
        """
        Exchange public keys with server.
        
        Protocol:
        1. Receive server's public key
        2. Send client's public key
        
        Returns:
            True if exchange successful, False otherwise
        """
        try:
            # Receive server's public key
            print("\n[Client] Receiving server's public key...")
            assert self.socket is not None, "Socket is not connected"
            data = self.socket.recv(4096).decode('utf-8')
            
            # Parse server's public key
            server_msg = json.loads(data)
            if server_msg.get('type') != 'KEY_EXCHANGE':
                print("Expected KEY_EXCHANGE message")
                return False
            
            self.server_public_key = (
                server_msg['public_key']['x'],
                server_msg['public_key']['y']
            )
            
            public_pem = KeyPair.from_coordinates(self.server_public_key)

            public_pem = public_pem.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            print(f"Server's public key received:\n{public_pem}")
            
            # Send client's public key
            print("[Client] Sending client's public key...")
            client_pub_x, client_pub_y = KeyPair.get_coordinates(self.client_public_key)
            
            key_msg = {
                'type': 'KEY_EXCHANGE',
                'public_key': {
                    'x': client_pub_x,
                    'y': client_pub_y
                }
            }
            
            #
            public_key_tuple = (client_pub_x, client_pub_y)
            client_public_key = KeyPair.from_coordinates(public_key_tuple)
            
            client_public_key = client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            print(f"[Client] Public key sent:\n{client_public_key}")
            
            assert self.socket is not None, "Socket is not connected"
            self.socket.send(json.dumps(key_msg).encode('utf-8'))
            print("Client's public key sent")
            
            return True
        except Exception as e:
            print(f"Key exchange failed: {e}")
            return False
    
    def send_secure_message(self, message_content: str) -> bool:
        """
        Encrypt and send a secure message using ExchangeManager.
        
        Pipeline:
        1. Create EmailMessage from content
        2. Use ExchangeManager to encrypt with Schnorr + RC6-GCM + El-Gamal
        3. Serialize SecureBundle to JSON
        4. Send over TCP socket
        
        Args:
            message_content: Plain text message to encrypt
            
        Returns:
            True if send successful, False otherwise
            
        Raises:
            Exception: If encryption fails
        """
        try:
            print(f"\n[Client] ENCRYPTION PIPELINE STARTING")
            print(f"{'='*70}")
            
            # Create email message
            print(f"\n[STEP 0] Preparing message")
            mail = EmailMessage(message_content)
            mail_bytes = mail.to_bytes()
            print(f"Input message: {message_content}")
            print(f"Message bytes length: {len(mail_bytes)}")
            print(f"Message hex: {mail_bytes.hex()[:64]}...")
            
            # Create manager and encrypt
            print(f"\n[STEP 1-3] THREE-LAYER ENCRYPTION PIPELINE")
            print(f" 1. Schnorr Signature Generation")
            print(f" 2. RC6-GCM Encryption")
            print(f" 3. Session Key Wrapping")
            
            if self.server_public_key is None:
                raise ValueError("Server public key not received. Please exchange keys first.")
            
            manager = ExchangeManager(self.client_private_key, self.server_public_key)
            bundle = manager.secure_send(mail)
            
            print(f"\nMessage encrypted successfully")
            print(f"{'='*70}")
            print(f"Ciphertext: {len(bundle.ciphertext)} bytes | {bundle.ciphertext.hex()[:64]}...")
            print(f"Session Key: {len(bundle.encrypted_key)} bytes | {bundle.encrypted_key.hex()[:32]}...")
            print(f"Auth Tag: {len(bundle.auth_tag)} bytes | {bundle.auth_tag.hex()}")
            print(f"IV: {len(bundle.iv)} bytes | {bundle.iv.hex()}")
            
            # Serialize bundle to JSON
            sender_pub_x, sender_pub_y = KeyPair.get_coordinates(bundle.sender_public_key)
            message_json = {
                'type': 'SECURE_MESSAGE',
                'encrypted_key': base64.b64encode(bundle.encrypted_key).decode('utf-8'),
                'iv': base64.b64encode(bundle.iv).decode('utf-8'),
                'ciphertext': base64.b64encode(bundle.ciphertext).decode('utf-8'),
                'auth_tag': base64.b64encode(bundle.auth_tag).decode('utf-8'),
                'sender_public_key': {
                    'x': sender_pub_x,
                    'y': sender_pub_y
                }
            }
            
            # Send encrypted message
            print("[Client] Sending encrypted message to server...")
            assert self.socket is not None, "Socket is not connected"
            self.socket.send(json.dumps(message_json).encode('utf-8'))
            print("Message sent")
            
            return True
        except Exception as e:
            print(f"Encryption/send failed: {e}")
            return False
    
    def receive_response(self) -> str:
        """
        Receive and display server response.
        
        Returns:
            Response message content, or empty string if failed
        """
        try:
            print("\n[Client] Waiting for server response...")
            assert self.socket is not None, "Socket is not connected"
            response_data = self.socket.recv(4096).decode('utf-8')
            
            if not response_data:
                print("✗ No response from server")
                return ""
            
            response = json.loads(response_data)
            
            if response.get('type') == 'ACK':
                print("Server acknowledged message")
                content = response.get('message', 'Message received')
                print(f"  - Response: {content}")
                return content
            elif response.get('type') == 'ERROR':
                print(f"Server error: {response.get('message')}")
                return ""
            else:
                print(f"Unknown response type: {response.get('type')}")
                return ""
        except Exception as e:
            print(f"Response receive failed: {e}")
            return ""
    
    def close(self) -> None:
        """
        Close socket connection.
        
        Sends DISCONNECT message and closes socket.
        """
        try:
            if self.socket:
                disconnect_msg = {'type': 'DISCONNECT'}
                self.socket.send(json.dumps(disconnect_msg).encode('utf-8'))
                self.socket.close()
                print("\n[Client] Disconnected")
        except Exception as e:
            print(f"Disconnect failed: {e}")
    
    def run_interactive(self) -> None:
        """
        Run client in interactive mode.
        
        User can send multiple messages until they enter 'quit'.
        
        Flow:
        1. Connect to server
        2. Exchange keys
        3. Loop: encrypt message → send → receive response
        4. Close connection
        """
        print("\n" + "="*70)
        print("SECURE CLIENT - Message Encryption Pipeline")
        print("="*70)
        
        # Connect
        if not self.connect():
            return
        
        # Exchange keys
        if not self.exchange_keys():
            self.close()
            return
        
        # Message loop
        print("\n[Client] Ready to send messages (type 'quit' to exit)")
        print("-"*70)
        
        while True:
            try:
                # Get message from user
                message = input("\n> Enter message (or 'quit'): ").strip()
                
                if message.lower() == 'quit':
                    break
                
                if not message:
                    continue
                
                # Send encrypted message
                if not self.send_secure_message(message):
                    continue
                
                # Receive response
                self.receive_response()
                
            except KeyboardInterrupt:
                print("\n\n[Client] Interrupted by user")
                break
            except Exception as e:
                print(f"Error: {e}")
                continue
        
        # Cleanup
        self.close()
        print("\n" + "="*70)
        print("Client session ended")
        print("="*70)


def main():
    """
    Main entry point for secure client.
    
    Usage:
        python src/secure_client.py [server_host] [server_port]
    
    If not enough arguments provided, prompts user for validated input.
    Defaults to connecting to 127.0.0.1:5000
    """
    # Check if sufficient arguments provided
    if len(sys.argv) < 3:
        # Get network config from user input with validation
        host, port = get_network_config(server_mode=False)
    else:
        # Use command-line arguments
        host = sys.argv[1]
        port = int(sys.argv[2])
        
        # Validate provided arguments
        if not validate_ip_address(host):
            print(f"Invalid IP address: {host}")
            sys.exit(1)
        if not validate_port(str(port)):
            print(f"Invalid port number: {port}")
            sys.exit(1)
    
    # Create and run client
    client = SecureClient(host=host, port=port)
    client.run_interactive()


if __name__ == "__main__":
    main()
