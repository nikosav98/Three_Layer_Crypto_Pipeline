"""
TCP Server for secure message exchange using Schnorr signatures + RC6-GCM + El Gamal.

Usage:
    from src.network.server import SecureServer
    server = SecureServer(host='localhost', port=5000)
    server.start()
"""

import socket
import threading
import logging
from typing import Dict, Tuple, Optional
from src.network.protocol import Protocol, MessageType
from src.utils.key_pair import KeyPair
from src.algorithms.schnorr.schnorr_signature import SchnorrSigner
from cryptography.hazmat.primitives.asymmetric import ec


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ClientHandler:
    """Handles a connected client."""
    
    def __init__(self, client_socket: socket.socket, client_address: Tuple, client_id: str):
        """
        Initialize client handler.
        
        Args:
            client_socket: Connected socket
            client_address: Client address (host, port)
            client_id: Unique client identifier
        """
        self.socket = client_socket
        self.address = client_address
        self.client_id = client_id
        self.client_public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.server_key_pair = KeyPair.generate()
        self.schnorr = SchnorrSigner()
    
    def receive_message(self) -> Tuple[Optional[MessageType], Optional[bytes]]:
        """
        Receive a complete message from client.
        
        Returns:
            (message_type, payload) or (None, None) on error/disconnect
        """
        try:
            # Receive header
            header = b''
            while len(header) < Protocol.HEADER_SIZE:
                chunk = self.socket.recv(Protocol.HEADER_SIZE - len(header))
                if not chunk:
                    return None, None
                header += chunk
            
            # Parse header to get payload length
            msg_type, payload_len = int.from_bytes(header[:4], 'big'), int.from_bytes(header[4:8], 'big')
            
            # Receive payload
            payload = b''
            while len(payload) < payload_len:
                chunk = self.socket.recv(min(4096, payload_len - len(payload)))
                if not chunk:
                    return None, None
                payload += chunk
            
            return MessageType(msg_type), payload
        except Exception as e:
            logger.error(f"Error receiving message from {self.client_id}: {e}")
            return None, None
    
    def send_message(self, msg_type: MessageType, payload: bytes) -> bool:
        """
        Send a message to client.
        
        Args:
            msg_type: Message type
            payload: Message payload
            
        Returns:
            True if successful, False otherwise
        """
        try:
            encoded = Protocol.encode_message(msg_type, payload)
            self.socket.sendall(encoded)
            return True
        except Exception as e:
            logger.error(f"Error sending message to {self.client_id}: {e}")
            return False
    
    def handle_key_exchange(self, payload: bytes) -> bool:
        """
        Handle key exchange (receive client's public key, send server's public key).
        
        Args:
            payload: Serialized key exchange data
            
        Returns:
            True if successful
        """
        try:
            # Deserialize client's public key
            data = Protocol.deserialize_key_exchange(payload)
            pub_key_x = data['pub_key_x']
            pub_key_y = data['pub_key_y']
            
            # Store client's public key (in real app, construct EC public key object)
            logger.info(f"Client {self.client_id} public key: ({pub_key_x}, {pub_key_y})")
            
            # Send server's public key
            server_pub = self.server_key_pair[1].public_numbers()
            response = Protocol.serialize_key_exchange(
                server_pub.x,
                server_pub.y,
                "server"
            )
            
            success = self.send_message(MessageType.KEY_EXCHANGE, response)
            if success:
                logger.info(f"Key exchange completed with {self.client_id}")
            return success
        except Exception as e:
            logger.error(f"Error in key exchange with {self.client_id}: {e}")
            return False
    
    def handle_secure_message(self, payload: bytes) -> bool:
        """
        Handle encrypted secure message.
        
        Args:
            payload: Serialized secure message
            
        Returns:
            True if successful
        """
        try:
            data = Protocol.deserialize_secure_message(payload)
            logger.info(f"Received secure message from {self.client_id}")
            logger.debug(f"  Encrypted key size: {len(data['encrypted_key'])} bytes")
            logger.debug(f"  Ciphertext size: {len(data['ciphertext'])} bytes")
            
            # Send acknowledgment
            ack_payload = Protocol.serialize_ack("success", "Message received")
            return self.send_message(MessageType.ACK, ack_payload)
        except Exception as e:
            logger.error(f"Error handling secure message from {self.client_id}: {e}")
            return False
    
    def close(self):
        """Close the client connection."""
        try:
            self.socket.close()
            logger.info(f"Connection closed for {self.client_id}")
        except:
            pass


class SecureServer:
    """
    TCP server for secure message exchange.
    
    Handles multiple clients with key exchange and encrypted message processing.
    """
    
    def __init__(self, host: str = 'localhost', port: int = 5000, max_clients: int = 10):
        """
        Initialize secure server.
        
        Args:
            host: Server host address
            port: Server port
            max_clients: Maximum concurrent clients
        """
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.clients: Dict[str, ClientHandler] = {}
        self.client_counter = 0
        self.lock = threading.Lock()
    
    def start(self):
        """Start the server and listen for connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_clients)
            self.server_socket.settimeout(1.0) # Check every second for a keyboard interrupt
            self.running = True
            
            logger.info(f"Server started on {self.host}:{self.port}")
            
            # Accept connections in main thread
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Complete the logic fully without stopping
                    client_socket.settimeout(None) 
                    
                    # Create unique client ID
                    with self.lock:
                        self.client_counter += 1
                        client_id = f"client_{self.client_counter}"
                    
                    logger.info(f"New connection from {client_address} (ID: {client_id})")
                    
                    # Handle client in separate thread
                    client_handler = ClientHandler(client_socket, client_address, client_id)
                    with self.lock:
                        self.clients[client_id] = client_handler
                    
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_id, client_handler),
                        daemon=True
                    )
                    thread.start()
                    
                except socket.timeout:
                    continue # On timeout, retry
                except KeyboardInterrupt:
                    logger.info("Server interrupted by user")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()
    
    def _handle_client(self, client_id: str, handler: ClientHandler):
        """
        Handle a connected client.
        
        Args:
            client_id: Client identifier
            handler: ClientHandler instance
        """
        try:
            while self.running:
                msg_type, payload = handler.receive_message()
                
                if msg_type is None:
                    logger.info(f"Client {client_id} disconnected")
                    break
                
                # Route message (payload can be empty for some message types)
                if msg_type == MessageType.KEY_EXCHANGE:
                    success = handler.handle_key_exchange(payload)
                    if not success:
                        handler.send_message(
                            MessageType.ERROR,
                            Protocol.serialize_error("Key exchange failed")
                        )
                elif msg_type == MessageType.SECURE_MESSAGE:
                    success = handler.handle_secure_message(payload)
                elif msg_type == MessageType.DISCONNECT:
                    logger.info(f"Client {client_id} requested disconnect")
                    break
                else:
                    logger.warning(f"Unknown message type from {client_id}: {msg_type}")
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            handler.close()
            with self.lock:
                if client_id in self.clients:
                    del self.clients[client_id]
    
    def stop(self):
        """Stop the server and close all connections."""
        self.running = False
        
        # Close all client connections
        with self.lock:
            for client_id, handler in list(self.clients.items()):
                handler.close()
            self.clients.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("Server stopped")
    
    def get_client_count(self) -> int:
        """Get number of connected clients."""
        with self.lock:
            return len(self.clients)
