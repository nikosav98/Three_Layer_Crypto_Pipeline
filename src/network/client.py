"""
TCP Client for secure message exchange using Schnorr signatures + RC6-GCM + El Gamal.

Usage:
    from src.network.client import SecureClient
    client = SecureClient(host='localhost', port=5000, client_id='user1')
    client.connect()
    client.send_secure_message(b'Hello, Server!')
    client.disconnect()
"""

import socket
import logging
from typing import Optional, Tuple
from src.network.protocol import Protocol, MessageType
from src.utils.key_pair import KeyPair
from src.algorithms.schnorr.schnorr_signature import SchnorrSigner
from cryptography.hazmat.primitives.asymmetric import ec


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecureClient:
    """
    TCP client for secure message exchange.
    
    Connects to server, performs key exchange, and sends/receives encrypted messages.
    """
    
    def __init__(self, host: str = 'localhost', port: int = 5000, client_id: str = 'client', timeout: float = 10.0):
        """
        Initialize secure client.
        
        Args:
            host: Server host address
            port: Server port
            client_id: Client identifier
            timeout: Socket timeout in seconds
        """
        self.host = host
        self.port = port
        self.client_id = client_id
        self.timeout = timeout
        self.socket: Optional[socket.socket] = None
        self.connected = False
        
        # Generate client key pair
        self.key_pair = KeyPair.generate()
        self.schnorr = SchnorrSigner()
        
        # Server's public key (received during key exchange)
        self.server_public_key: Optional[dict] = None
    
    def connect(self) -> bool:
        """
        Connect to the server and perform key exchange.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            logger.info(f"Connected to server at {self.host}:{self.port}")
            
            # Perform key exchange
            if self._key_exchange():
                logger.info("Key exchange successful")
                return True
            else:
                logger.error("Key exchange failed")
                self.disconnect()
                return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def _key_exchange(self) -> bool:
        """
        Perform key exchange with server.
        
        Returns:
            True if successful
        """
        try:
            # Get client public key
            client_pub = self.key_pair[1].public_numbers()
            
            # Send client's public key
            payload = Protocol.serialize_key_exchange(
                client_pub.x,
                client_pub.y,
                self.client_id
            )
            
            if not self._send_message(MessageType.KEY_EXCHANGE, payload):
                logger.error("Failed to send key exchange message")
                return False
            
            # Receive server's public key
            msg_type, response_payload = self._receive_message()
            
            if msg_type != MessageType.KEY_EXCHANGE:
                logger.error(f"Unexpected response: {msg_type}")
                return False
            
            # Check if message type is correct
            if msg_type != MessageType.KEY_EXCHANGE:
                raise Exception(f"Expected KEY_EXCHANGE, got {msg_type}")
            
            # Deserialize server's public key
            data = Protocol.deserialize_key_exchange(response_payload)
            self.server_public_key = data
            logger.info(f"Server public key: ({data['pub_key_x']}, {data['pub_key_y']})")
            
            return True
        except Exception as e:
            logger.error(f"Key exchange error: {e}")
            return False
    
    def _send_message(self, msg_type: MessageType, payload: bytes) -> bool:
        """
        Send a message to server.
        
        Args:
            msg_type: Message type
            payload: Message payload
            
        Returns:
            True if successful
        """
        try:
            if not self.connected:
                logger.error("Not connected to server")
                return False
            
            encoded = Protocol.encode_message(msg_type, payload)
            self.socket.sendall(encoded)
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.connected = False
            return False
    
    def _receive_message(self) -> Tuple[Optional[MessageType], Optional[bytes]]:
        """
        Receive a message from server.
        
        Returns:
            (message_type, payload) or (None, None) on error
        """
        try:
            if not self.connected:
                logger.error("Not connected to server")
                return None, None
            
            # Receive header
            header = b''
            while len(header) < Protocol.HEADER_SIZE:
                chunk = self.socket.recv(Protocol.HEADER_SIZE - len(header))
                if not chunk:
                    logger.error("Server closed connection")
                    self.connected = False
                    return None, None
                header += chunk
            
            # Parse header
            msg_type, payload_len = int.from_bytes(header[:4], 'big'), int.from_bytes(header[4:8], 'big')
            
            # Receive payload
            payload = b''
            while len(payload) < payload_len:
                chunk = self.socket.recv(min(4096, payload_len - len(payload)))
                if not chunk:
                    logger.error("Server closed connection")
                    self.connected = False
                    return None, None
                payload += chunk
            
            return MessageType(msg_type), payload
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            self.connected = False
            return None, None
    
    def send_secure_message(
        self,
        encrypted_key: bytes,
        iv: bytes,
        ciphertext: bytes,
        auth_tag: bytes
    ) -> bool:
        """
        Send encrypted secure message to server.
        
        Args:
            encrypted_key: Encrypted session key
            iv: Initialization vector
            ciphertext: Encrypted message
            auth_tag: Authentication tag
            
        Returns:
            True if successful
        """
        try:
            payload = Protocol.serialize_secure_message(
                encrypted_key,
                iv,
                ciphertext,
                auth_tag,
                self.client_id
            )
            
            if not self._send_message(MessageType.SECURE_MESSAGE, payload):
                logger.error("Failed to send secure message")
                return False
            
            # Wait for acknowledgment
            msg_type, ack_payload = self._receive_message()
            
            # Check if message type is correct
            if msg_type is None:
                raise Exception("Server closed connection")
                     
            if msg_type == MessageType.ACK:
                ack = Protocol.deserialize_ack(ack_payload)
                logger.info(f"Server acknowledged: {ack['message']}")
                return True
            elif msg_type == MessageType.ERROR:
                error = Protocol.deserialize_error(ack_payload)
                logger.error(f"Server error: {error}")
                return False
            else:
                logger.error(f"Unexpected response: {msg_type}")
                return False
        except Exception as e:
            logger.error(f"Error sending secure message: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server."""
        if self.connected:
            try:
                # Send disconnect message
                self._send_message(MessageType.DISCONNECT, b'')
            except Exception as e:
                logger.debug(f"Error sending disconnect: {e}")
            finally:
                if self.socket:
                    try:
                        self.socket.close()
                    except:
                        pass
                self.connected = False
                logger.info("Disconnected from server")
    
    def is_connected(self) -> bool:
        """Check if client is connected to server."""
        return self.connected


if __name__ == "__main__":
    # Example usage
    client = SecureClient(host='localhost', port=5000, client_id='test_client')
    
    if client.connect():
        logger.info("Successfully connected to server")
        
        # Example: send a secure message (with dummy encrypted data)
        # In real use, encrypt using ExchangeManager
        dummy_encrypted_key = b'0' * 64
        dummy_iv = b'0' * 12
        dummy_ciphertext = b'0' * 100
        dummy_tag = b'0' * 16
        
        client.send_secure_message(
            dummy_encrypted_key,
            dummy_iv,
            dummy_ciphertext,
            dummy_tag
        )
        
        # Disconnect
        client.disconnect()
    else:
        logger.error("Failed to connect to server")
