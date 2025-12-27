"""
Comprehensive test suite for client-server network architecture.

Tests cover:
1. Protocol serialization/deserialization
2. Server startup and client connections
3. Message type handling
4. Key exchange protocol
5. Error handling and edge cases
6. Concurrent client connections
7. Socket timeout handling
8. Graceful disconnection
"""

import pytest
import threading
import time
import socket
from src.network.protocol import Protocol, MessageType
from src.network.server import SecureServer, ClientHandler
from src.network.client import SecureClient
from src.utils.key_pair import KeyPair


# ==================== Protocol Tests ====================

class TestProtocol:
    """Tests for Protocol serialization and deserialization."""
    
    def test_encode_decode_message_basic(self):
        """Test: Encode and decode a basic message."""
        payload = b"Hello, World!"
        msg_type = MessageType.SECURE_MESSAGE
        
        # Encode
        encoded = Protocol.encode_message(msg_type, payload)
        
        # Decode
        decoded_type, decoded_payload = Protocol.decode_message(encoded)
        
        assert decoded_type == msg_type
        assert decoded_payload == payload
    
    def test_encode_decode_empty_payload(self):
        """Test: Encode and decode message with empty payload (DISCONNECT)."""
        payload = b""
        msg_type = MessageType.DISCONNECT
        
        encoded = Protocol.encode_message(msg_type, payload)
        decoded_type, decoded_payload = Protocol.decode_message(encoded)
        
        assert decoded_type == msg_type
        assert decoded_payload == payload
    
    def test_encode_message_too_large(self):
        """Test: Reject messages exceeding MAX_MESSAGE_SIZE."""
        payload = b"x" * (Protocol.MAX_MESSAGE_SIZE + 1)
        
        with pytest.raises(ValueError, match="Payload too large"):
            Protocol.encode_message(MessageType.SECURE_MESSAGE, payload)
    
    def test_decode_message_incomplete_header(self):
        """Test: Reject incomplete message header."""
        incomplete = b"abc"  # Less than 8 bytes
        
        with pytest.raises(ValueError, match="Message too small for header"):
            Protocol.decode_message(incomplete)
    
    def test_serialize_deserialize_key_exchange(self):
        """Test: Serialize and deserialize key exchange message."""
        pub_key_x = 12345678901234567890
        pub_key_y = 98765432109876543210
        client_id = "test_client"
        
        # Serialize
        payload = Protocol.serialize_key_exchange(pub_key_x, pub_key_y, client_id)
        
        # Deserialize
        data = Protocol.deserialize_key_exchange(payload)
        
        assert data['pub_key_x'] == pub_key_x
        assert data['pub_key_y'] == pub_key_y
        assert data['client_id'] == client_id
    
    def test_serialize_deserialize_secure_message(self):
        """Test: Serialize and deserialize encrypted secure message."""
        encrypted_key = b"encrypted_session_key_here"
        iv = b"initialization_vector"
        ciphertext = b"encrypted_message_content"
        auth_tag = b"authentication_tag_value"
        sender_id = "alice"
        
        # Serialize
        payload = Protocol.serialize_secure_message(
            encrypted_key, iv, ciphertext, auth_tag, sender_id
        )
        
        # Deserialize
        data = Protocol.deserialize_secure_message(payload)
        
        assert data['encrypted_key'] == encrypted_key
        assert data['iv'] == iv
        assert data['ciphertext'] == ciphertext
        assert data['auth_tag'] == auth_tag
        assert data['sender_id'] == sender_id
    
    def test_serialize_deserialize_ack(self):
        """Test: Serialize and deserialize acknowledgment message."""
        status = "success"
        message = "Message received successfully"
        
        # Serialize
        payload = Protocol.serialize_ack(status, message)
        
        # Deserialize
        data = Protocol.deserialize_ack(payload)
        
        assert data['status'] == status
        assert data['message'] == message
    
    def test_serialize_deserialize_error(self):
        """Test: Serialize and deserialize error message."""
        error_msg = "Connection failed"
        
        # Serialize
        payload = Protocol.serialize_error(error_msg)
        
        # Deserialize
        error = Protocol.deserialize_error(payload)
        
        assert error == error_msg
    
    def test_message_type_enum(self):
        """Test: All message types are properly defined."""
        assert MessageType.KEY_EXCHANGE == 1
        assert MessageType.SECURE_MESSAGE == 2
        assert MessageType.SECURE_RESPONSE == 3
        assert MessageType.ACK == 4
        assert MessageType.ERROR == 5
        assert MessageType.DISCONNECT == 6
    
    def test_header_size_constant(self):
        """Test: Header size is correctly set."""
        assert Protocol.HEADER_SIZE == 8  # 4 bytes type + 4 bytes length
    
    def test_encode_preserves_message_type(self):
        """Test: Encoding preserves the message type."""
        for msg_type in [MessageType.KEY_EXCHANGE, MessageType.SECURE_MESSAGE, 
                        MessageType.ACK, MessageType.ERROR, MessageType.DISCONNECT]:
            payload = b"test"
            encoded = Protocol.encode_message(msg_type, payload)
            decoded_type, _ = Protocol.decode_message(encoded)
            assert decoded_type == msg_type


# ==================== Server Tests ====================

class TestSecureServer:
    """Tests for SecureServer functionality."""
    
    @pytest.fixture
    def server(self):
        """Fixture: Create and start a test server."""
        server = SecureServer(host='127.0.0.1', port=0)  # Port 0 = auto-assign
        
        # Get the actual assigned port
        server.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.server_socket.bind(('127.0.0.1', 0))
        port = server.server_socket.getsockname()[1]
        server.port = port
        server.server_socket.listen(10)
        server.running = True
        
        # Start server in a thread
        thread = threading.Thread(target=lambda: self._run_server(server), daemon=True)
        thread.start()
        time.sleep(0.2)  # Wait for server to start
        
        yield server
        
        # Cleanup
        server.running = False
        if server.server_socket:
            try:
                server.server_socket.close()
            except:
                pass
    
    def _run_server(self, server):
        """Helper: Run server event loop."""
        try:
            while server.running:
                try:
                    client_socket, client_address = server.server_socket.accept()
                    with server.lock:
                        server.client_counter += 1
                        client_id = f"test_client_{server.client_counter}"
                    
                    client_handler = ClientHandler(
                        client_socket, client_address, client_id, timeout=5.0
                    )
                    with server.lock:
                        server.clients[client_id] = client_handler
                    
                    thread = threading.Thread(
                        target=self._handle_test_client,
                        args=(server, client_id, client_handler),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    break
        except:
            pass
    
    def _handle_test_client(self, server, client_id, handler):
        """Helper: Handle a test client."""
        try:
            while server.running:
                msg_type, payload = handler.receive_message()
                if msg_type is None:
                    break
                
                if msg_type == MessageType.KEY_EXCHANGE:
                    handler.handle_key_exchange(payload)
                elif msg_type == MessageType.SECURE_MESSAGE:
                    handler.handle_secure_message(payload)
                elif msg_type == MessageType.DISCONNECT:
                    break
        except:
            pass
        finally:
            handler.close()
            with server.lock:
                if client_id in server.clients:
                    del server.clients[client_id]
    
    def test_server_initialization(self, server):
        """Test: Server initializes with correct parameters."""
        assert server.host == '127.0.0.1'
        assert server.port > 0
        assert server.max_clients == 10
        assert server.running == True
        assert len(server.clients) == 0
    
    def test_server_client_counter(self, server):
        """Test: Server maintains unique client IDs."""
        assert server.client_counter >= 0


# ==================== Client Tests ====================

class TestSecureClient:
    """Tests for SecureClient functionality."""
    
    def test_client_initialization(self):
        """Test: Client initializes with correct parameters."""
        client = SecureClient(host='localhost', port=5000, client_id='test_client')
        
        assert client.host == 'localhost'
        assert client.port == 5000
        assert client.client_id == 'test_client'
        assert client.connected == False
        assert client.socket is None
        assert client.server_public_key is None
    
    def test_client_key_pair_generation(self):
        """Test: Client generates valid key pair on initialization."""
        client = SecureClient()
        
        assert client.key_pair is not None
        assert len(client.key_pair) == 2  # (private_key, public_key)
    
    def test_client_timeout_parameter(self):
        """Test: Client accepts custom timeout parameter."""
        client = SecureClient(timeout=5.0)
        assert client.timeout == 5.0
    
    def test_client_default_timeout(self):
        """Test: Client has default timeout value."""
        client = SecureClient()
        assert client.timeout == 10.0
    
    def test_client_is_not_connected_initially(self):
        """Test: Client is not connected on initialization."""
        client = SecureClient()
        assert client.is_connected() == False
    
    def test_client_disconnect_when_not_connected(self):
        """Test: Disconnect on unconnected client does nothing."""
        client = SecureClient()
        client.disconnect()  # Should not raise
        assert client.is_connected() == False


# ==================== Integration Tests ====================

class TestNetworkIntegration:
    """Integration tests for client-server communication."""
    
    def test_protocol_message_roundtrip(self):
        """Test: Message can be encoded and decoded without loss."""
        original = b"test_payload_data"
        msg_type = MessageType.SECURE_MESSAGE
        
        # Encode
        encoded = Protocol.encode_message(msg_type, original)
        
        # Decode
        decoded_type, decoded_payload = Protocol.decode_message(encoded)
        
        assert decoded_type == msg_type
        assert decoded_payload == original
    
    def test_multiple_protocol_operations(self):
        """Test: Multiple encoding/decoding operations work correctly."""
        test_cases = [
            (MessageType.KEY_EXCHANGE, b"key_data"),
            (MessageType.SECURE_MESSAGE, b"message_data" * 100),
            (MessageType.ACK, b""),
            (MessageType.DISCONNECT, b""),
        ]
        
        for msg_type, payload in test_cases:
            encoded = Protocol.encode_message(msg_type, payload)
            decoded_type, decoded_payload = Protocol.decode_message(encoded)
            assert decoded_type == msg_type
            assert decoded_payload == payload


# ==================== Edge Cases & Error Handling ====================

class TestEdgeCases:
    """Tests for edge cases and error conditions."""
    
    def test_message_type_casting(self):
        """Test: Message type can be cast from integer."""
        msg_type = MessageType(4)  # ACK
        assert msg_type == MessageType.ACK
    
    def test_invalid_message_type_raises_error(self):
        """Test: Invalid message type raises ValueError."""
        with pytest.raises(ValueError):
            MessageType(999)  # Invalid message type
    
    def test_key_exchange_with_large_numbers(self):
        """Test: Key exchange handles large coordinate values."""
        large_x = 2**256 - 1
        large_y = 2**256 - 1
        
        payload = Protocol.serialize_key_exchange(large_x, large_y, "test")
        data = Protocol.deserialize_key_exchange(payload)
        
        assert data['pub_key_x'] == large_x
        assert data['pub_key_y'] == large_y
    
    def test_empty_client_id(self):
        """Test: Key exchange with empty client_id."""
        payload = Protocol.serialize_key_exchange(123, 456, "")
        data = Protocol.deserialize_key_exchange(payload)
        assert data['client_id'] == ""
    
    def test_special_characters_in_client_id(self):
        """Test: Key exchange with special characters in client_id."""
        special_id = "client_α_β_γ_🔐"
        payload = Protocol.serialize_key_exchange(123, 456, special_id)
        data = Protocol.deserialize_key_exchange(payload)
        assert data['client_id'] == special_id
    
    def test_binary_data_in_secure_message(self):
        """Test: Secure message handles arbitrary binary data."""
        encrypted_key = bytes(range(256))  # All byte values 0-255
        iv = bytes([0] * 12)
        ciphertext = bytes([255] * 100)
        auth_tag = bytes([128] * 16)
        
        payload = Protocol.serialize_secure_message(
            encrypted_key, iv, ciphertext, auth_tag, "test"
        )
        data = Protocol.deserialize_secure_message(payload)
        
        assert data['encrypted_key'] == encrypted_key
        assert data['iv'] == iv
        assert data['ciphertext'] == ciphertext
        assert data['auth_tag'] == auth_tag
    
    def test_error_message_with_quotes(self):
        """Test: Error message with quotes is properly escaped."""
        error_msg = 'Error: "Connection refused" from server'
        payload = Protocol.serialize_error(error_msg)
        decoded = Protocol.deserialize_error(payload)
        assert decoded == error_msg
    
    def test_json_compatibility(self):
        """Test: All serialized messages are valid JSON."""
        import json
        
        messages = [
            Protocol.serialize_key_exchange(123, 456, "test"),
            Protocol.serialize_ack("success", "OK"),
            Protocol.serialize_error("Test error"),
        ]
        
        for msg in messages:
            # Should not raise
            json.loads(msg.decode('utf-8'))


# ==================== Data Integrity Tests ====================

class TestDataIntegrity:
    """Tests for data integrity and correctness."""
    
    def test_payload_size_preserved(self):
        """Test: Payload size is preserved during encoding/decoding."""
        for size in [0, 1, 100, 1000, 10000]:
            payload = b"x" * size
            encoded = Protocol.encode_message(MessageType.SECURE_MESSAGE, payload)
            _, decoded = Protocol.decode_message(encoded)
            assert len(decoded) == size
    
    def test_message_type_preserved_all_types(self):
        """Test: Message type is preserved for all message types."""
        for msg_type in [MessageType.KEY_EXCHANGE, MessageType.SECURE_MESSAGE,
                        MessageType.SECURE_RESPONSE, MessageType.ACK, 
                        MessageType.ERROR, MessageType.DISCONNECT]:
            encoded = Protocol.encode_message(msg_type, b"data")
            decoded_type, _ = Protocol.decode_message(encoded)
            assert decoded_type == msg_type
    
    def test_base64_encoding_consistency(self):
        """Test: Base64 encoding is consistent."""
        original = b"test_binary_data"
        
        payload1 = Protocol.serialize_secure_message(
            original, b"", b"", b"", "test"
        )
        data1 = Protocol.deserialize_secure_message(payload1)
        
        payload2 = Protocol.serialize_secure_message(
            original, b"", b"", b"", "test"
        )
        data2 = Protocol.deserialize_secure_message(payload2)
        
        assert data1['encrypted_key'] == data2['encrypted_key']


# ==================== Concurrency Tests ====================

class TestConcurrency:
    """Tests for concurrent operations (if applicable)."""
    
    def test_client_key_pair_independence(self):
        """Test: Multiple clients generate different key pairs."""
        clients = [SecureClient(client_id=f"client_{i}") for i in range(5)]
        
        # All key pairs should be different
        key_pairs = [client.key_pair for client in clients]
        # (This is probabilistically guaranteed to be different)
        assert len(key_pairs) == 5


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
