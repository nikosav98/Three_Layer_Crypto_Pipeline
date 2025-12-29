"""
Secure Server Application - Receives and decrypts messages from clients.

This server implements the complete decryption pipeline:
1. Generates/loads key pair (SECP256K1)
2. Accepts client connections
3. Exchanges public keys with clients
4. Receives encrypted SecureBundle
5. Uses ExchangeManager to decrypt with three-layer pipeline:
   - El-Gamal unwraps session key
   - RC6-GCM decrypts message
   - Schnorr verifies signature
6. Processes and responds to client

Protocol:
    1. ACCEPT client connection
    2. SEND server's public key (KEY_EXCHANGE)
    3. RECEIVE client's public key (KEY_EXCHANGE)
    4. RECEIVE encrypted message (SECURE_MESSAGE)
    5. DECRYPT and verify using ExchangeManager
    6. SEND ACK or ERROR response
    7. CLOSE connection or DISCONNECT

Usage:
    python src/secure_server.py
    
    Server starts on 0.0.0.0:5000 and waits for client connections.
    Each client connection is handled in a separate thread.
    
References:
    - Message Format: SecureBundle (encrypted_key, iv, ciphertext, auth_tag, sender_pub_key)
    - Decryption: El-Gamal + RC6-GCM + Schnorr (reverse of 3-layer pipeline)
    - Transport: TCP socket with JSON serialization
    - Threading: Thread-per-client model for concurrent handling
"""

import socket
import json
import base64
import os
import sys
import threading
import time
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.key_pair import KeyPair
from src.algorithms.key_exchange.exchange_manager import ExchangeManager


class SecureServer:
    """
    Secure server for encrypted message reception and decryption.
    
    Handles:
    - Key pair management (SECP256K1)
    - Client connection acceptance
    - Key exchange protocol
    - Message decryption with ExchangeManager
    - Response generation
    - Multi-threaded client handling
    
    Attributes:
        host: Binding IP address
        port: Binding port number
        server_private_key: Server's EC private key
        server_public_key: Server's EC public key
        server_socket: TCP server socket
        running: Flag indicating if server is running
        client_count: Number of connected clients
        max_clients: Maximum concurrent connections
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5000, 
                 max_clients: int = 10) -> None:
        """
        Initialize secure server.
        
        Args:
            host: IP address to bind to (default: all interfaces)
            port: Port number to listen on
            max_clients: Maximum number of concurrent clients
            
        Raises:
            Exception: If key generation fails
        """
        self.host = host
        self.port = port
        self.max_clients = max_clients
        
        # Generate server's key pair
        print("[Server] Generating key pair...")
        self.server_private_key, self.server_public_key = KeyPair.generate()
        
        # Serialize keys so they can be printed
        private_pem = self.server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Serialize Public Key
        public_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        print("Key pair generated"
              f"\nServer private key:\n{private_pem}"
              f"\nServer public key:\n{public_pem}")
        
        self.server_socket = None
        self.running = False
        self.client_count = 0
        self.client_lock = threading.Lock()
    
    def start(self) -> None:
        """
        Start the secure server.
        
        - Creates and binds server socket
        - Listens for incoming connections
        - Spawns client handler threads
        - Handles KeyboardInterrupt gracefully
        
        Flow:
        1. Create socket and bind to port
        2. Listen for incoming connections
        3. Accept connections in loop
        4. Spawn ClientHandler thread for each connection
        5. Monitor client count
        """
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Add server timeout to allow keyboard interrupt to be read
            self.server_socket.settimeout(1.0) # Check every second
            
            # Bind and listen
            print(f"\n[Server] Binding to {self.host}:{self.port}")
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_clients)
            self.running = True
            print(f"Server listening on {self.host}:{self.port}")
            print("Ctrl+C to shutdown server")
            print("-"*70)
            
            # Accept connections
            while self.running:
                try:
                    # Accept client connection
                    client_socket, client_addr = self.server_socket.accept()
                    
                    # Check max clients
                    with self.client_lock:
                        if self.client_count >= self.max_clients:
                            print(f"\nMax clients reached, rejecting {client_addr}")
                            client_socket.close()
                            continue
                        
                        self.client_count += 1
                        client_id = self.client_count
                    
                    print(f"\n[Server] New connection from {client_addr} (Client #{client_id})")
                    
                    # Spawn client handler thread
                    handler = ClientHandler(
                        client_id=client_id,
                        client_socket=client_socket,
                        client_addr=client_addr,
                        server_private_key=self.server_private_key,
                        server_public_key=self.server_public_key,
                        server=self
                    )
                    
                    handler_thread = threading.Thread(target=handler.handle, daemon=True)
                    handler_thread.start()
                
                except socket.timeout:
                    continue
                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
        
        except socket.error as e:
            print(f"Server socket error: {e}")
        except KeyboardInterrupt:
            print("\n[Server] Interrupt received")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """
        Stop the secure server.
        
        - Sets running flag to False
        - Closes server socket
        - Gracefully handles pending connections
        """
        print("\n[Server] Shutting down...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
                print("Server socket closed")
            except:
                pass
        
        print("Server stopped")
    
    def client_disconnected(self) -> None:
        """
        Called when a client disconnects.
        
        Decrements client counter.
        """
        with self.client_lock:
            self.client_count = max(0, self.client_count - 1)


class ClientHandler:
    """
    Handles individual client connections.
    
    Manages:
    - Key exchange with client
    - Message decryption
    - Response generation
    - Connection cleanup
    
    Attributes:
        client_id: Unique identifier for this client
        client_socket: Socket connection to client
        client_addr: Client's address tuple (host, port)
        client_public_key: Client's EC public key
        server_private_key: Server's EC private key
        server_public_key: Server's EC public key
        server: Parent SecureServer instance
    """
    
    def __init__(self, client_id: int, client_socket: socket.socket,
                 client_addr: Tuple[str, int], server_private_key,
                 server_public_key, server: 'SecureServer') -> None:
        """
        Initialize client handler.
        
        Args:
            client_id: Unique client identifier
            client_socket: Connected socket to client
            client_addr: Client's (host, port)
            server_private_key: Server's EC private key
            server_public_key: Server's EC public key
            server: Parent SecureServer instance
        """
        self.client_id = client_id
        self.client_socket = client_socket
        self.client_addr = client_addr
        self.client_public_key = None
        self.server_private_key = server_private_key
        self.server_public_key = server_public_key
        self.server = server
    
    def handle(self) -> None:
        """
        Handle client connection lifecycle.
        
        Protocol:
        1. Exchange public keys
        2. Receive encrypted messages
        3. Decrypt and process
        4. Send responses
        5. Handle disconnect
        
        Flow:
        1. Send server's public key
        2. Receive client's public key
        3. Enter message handling loop
        4. For each message: decrypt → verify → respond
        5. Handle DISCONNECT or errors
        """
        try:
            # Exchange keys
            if not self._exchange_keys():
                return
            
            # Message handling loop
            while True:
                if not self._handle_message():
                    break
        
        except Exception as e:
            print(f"[Client #{self.client_id}] Error: {e}")
        finally:
            self._cleanup()
    
    def _exchange_keys(self) -> bool:
        """
        Exchange public keys with client.
        
        Protocol:
        1. Send server's public key
        2. Receive client's public key
        
        Returns:
            True if exchange successful, False otherwise
        """
        try:
            # Send server's public key
            print(f"[Client #{self.client_id}] Sending server's public key...")
            server_pub_x, server_pub_y = KeyPair.get_coordinates(self.server_public_key)
            
            key_msg = {
                'type': 'KEY_EXCHANGE',
                'public_key': {
                    'x': server_pub_x,
                    'y': server_pub_y
                }
            }
            
            self.client_socket.send(json.dumps(key_msg).encode('utf-8'))
            print(f"[Client #{self.client_id}] Server's public key sent")
            
            # Receive client's public key
            print(f"[Client #{self.client_id}] Waiting for client's public key...")
            data = self.client_socket.recv(4096).decode('utf-8')
            
            if not data:
                print(f"[Client #{self.client_id}] No data received")
                return False
            
            client_msg = json.loads(data)
            if client_msg.get('type') != 'KEY_EXCHANGE':
                print(f"[Client #{self.client_id}] Expected KEY_EXCHANGE")
                return False
            
            self.client_public_key = (
                client_msg['public_key']['x'],
                client_msg['public_key']['y']
            )
            print(f"[Client #{self.client_id}] Client's public key received")
            
            return True
        except Exception as e:
            print(f"[Client #{self.client_id}] Key exchange failed: {e}")
            return False
    
    def _handle_message(self) -> bool:
        """
        Handle single message from client.
        
        Process:
        1. Receive SECURE_MESSAGE or DISCONNECT
        2. If DISCONNECT: return False (end loop)
        3. If SECURE_MESSAGE:
           - Deserialize JSON
           - Decrypt using ExchangeManager
           - Process decrypted message
           - Send ACK response
        4. If error: send ERROR response
        
        Returns:
            False if client disconnected, True if handled successfully
        """
        try:
            # Receive message
            print(f"[Client #{self.client_id}] Waiting for message...")
            data = self.client_socket.recv(8192).decode('utf-8')
            
            if not data:
                print(f"[Client #{self.client_id}] Client closed connection")
                return False
            
            msg = json.loads(data)
            msg_type = msg.get('type')
            
            # Handle DISCONNECT
            if msg_type == 'DISCONNECT':
                print(f"[Client #{self.client_id}] Client disconnecting")
                return False
            
            # Handle SECURE_MESSAGE
            if msg_type == 'SECURE_MESSAGE':
                return self._decrypt_and_respond(msg)
            
            # Unknown message type
            print(f"[Client #{self.client_id}] Unknown message type: {msg_type}")
            self._send_error("Unknown message type")
            return False
        
        except json.JSONDecodeError:
            print(f"[Client #{self.client_id}] Invalid JSON received")
            self._send_error("Invalid JSON")
            return True
        except Exception as e:
            print(f"[Client #{self.client_id}] Error handling message: {e}")
            self._send_error(str(e))
            return True
    
    def _decrypt_and_respond(self, msg: dict) -> bool:
        """
        Decrypt secure message and send response.
        
        Process:
        1. Extract encrypted components from JSON
        2. Create SecureBundle
        3. Use ExchangeManager to decrypt
        4. Verify signature and authenticate
        5. Process decrypted message
        6. Send ACK response
        
        Args:
            msg: SECURE_MESSAGE dict from client
            
        Returns:
            True if handled, False on error
        """
        try:
            print(f"\n[Client #{self.client_id}] DECRYPTION PIPELINE STARTING")
            print(f"{'='*70}")
            print(f"[Client #{self.client_id}] Extracting message components...")
            
            # Reconstruct SecureBundle from JSON
            from src.utils.secure_bundle import SecureBundle
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend
            
            # Decode encrypted_key from base64
            encrypted_key_bytes = base64.b64decode(msg['encrypted_key'])
            print(f"[Client #{self.client_id}]\tSession Key: {len(encrypted_key_bytes)} bytes | {encrypted_key_bytes.hex()[:32]}...")
            
            # Reconstruct sender's public key from (x, y) coordinates
            x = msg['sender_public_key']['x']
            y = msg['sender_public_key']['y']
            print(f"[Client #{self.client_id}]\tSender Public Key: x={str(x)[:32]}... y={str(y)[:32]}...")
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
            sender_public_key = public_numbers.public_key(default_backend())
            
            # Decode ciphertext and auth tag
            iv_bytes = base64.b64decode(msg['iv'])
            ciphertext_bytes = base64.b64decode(msg['ciphertext'])
            auth_tag_bytes = base64.b64decode(msg['auth_tag'])
            print(f"[Client #{self.client_id}]\tIV: {len(iv_bytes)} bytes | {iv_bytes.hex()}")
            print(f"[Client #{self.client_id}]\tCiphertext: {len(ciphertext_bytes)} bytes | {ciphertext_bytes.hex()[:64]}...")
            print(f"[Client #{self.client_id}]\tAuth Tag: {len(auth_tag_bytes)} bytes | {auth_tag_bytes.hex()}")
            
            # Create SecureBundle with decoded data
            bundle = SecureBundle(
                ek=encrypted_key_bytes,
                iv=iv_bytes,
                c=ciphertext_bytes,
                t=auth_tag_bytes,
                sender_pub_key=sender_public_key,
                sender_id="client"
            )
            
            # Decrypt using ExchangeManager
            print(f"\n[Client #{self.client_id}] Starting THREE-LAYER DECRYPTION")
            print('-' * 70)
            manager = ExchangeManager(
                self.server_private_key,
                bundle.sender_public_key
            )
            
            plaintext = manager.secure_receive(bundle, self.server_private_key)
            
            print(f"{'='*70}")
            print(f"[Client #{self.client_id}] Message decrypted successfully")
            print(f"Final message: {plaintext}")
            
            # Send ACK
            ack_msg = {
                'type': 'ACK',
                'message': 'Message received and verified'
            }
            self.client_socket.send(json.dumps(ack_msg).encode('utf-8'))
            print(f"[Client #{self.client_id}] ACK sent")
            
            return True
        
        except ValueError as e:
            print(f"[Client #{self.client_id}] Decryption/verification failed: {e}")
            self._send_error(f"Decryption failed: {str(e)}")
            return True
        except Exception as e:
            print(f"[Client #{self.client_id}] Error decrypting: {e}")
            self._send_error(str(e))
            return True
    
    def _send_error(self, message: str) -> None:
        """
        Send ERROR response to client.
        
        Args:
            message: Error message to send
        """
        try:
            error_msg = {
                'type': 'ERROR',
                'message': message
            }
            self.client_socket.send(json.dumps(error_msg).encode('utf-8'))
        except:
            pass
    
    def _cleanup(self) -> None:
        """
        Clean up client connection.
        
        - Close socket
        - Update server's client count
        - Print disconnect message
        """
        try:
            self.client_socket.close()
            print(f"[Client #{self.client_id}] Disconnected")
        except:
            pass
        
        self.server.client_disconnected()


def main():
    """
    Main entry point for secure server.
    
    Usage:
        python src/secure_server.py [host] [port] [max_clients]
    
    Defaults:
        - host: 0.0.0.0 (all interfaces)
        - port: 5000
        - max_clients: 10
    """
    # Parse arguments
    host = "0.0.0.0" if len(sys.argv) < 2 else sys.argv[1]
    port = 5000 if len(sys.argv) < 3 else int(sys.argv[2])
    max_clients = 10 if len(sys.argv) < 4 else int(sys.argv[3])
    
    # Print header
    print("\n" + "="*70)
    print("SECURE SERVER - Message Decryption Pipeline")
    print("="*70)
    
    # Create and run server
    server = SecureServer(host=host, port=port, max_clients=max_clients)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[Server] Interrupted by user")


if __name__ == "__main__":
    main()
