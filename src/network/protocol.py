"""
Network protocol definitions for secure message transmission.

Message format: [TYPE:4][LENGTH:4][PAYLOAD:variable]
Where:
- TYPE: 4 bytes indicating message type
- LENGTH: 4 bytes indicating payload size
- PAYLOAD: variable size data
"""

import json
import struct
from enum import IntEnum
from typing import Any, Tuple


class MessageType(IntEnum):
    """Message types for client-server communication."""
    KEY_EXCHANGE = 1          # Exchange EC public keys
    SECURE_MESSAGE = 2        # Send encrypted secure message
    SECURE_RESPONSE = 3       # Response to secure message
    ACK = 4                   # Acknowledgment
    ERROR = 5                 # Error message
    DISCONNECT = 6            # Clean disconnect
    AUTH_REGISTER = 7         # User registration
    AUTH_LOGIN = 8            # User login
    AUTH_SUCCESS = 9          # Authentication successful
    AUTH_FAILURE = 10         # Authentication failed


class Protocol:
    """Protocol handler for serializing/deserializing network messages."""
    
    HEADER_SIZE = 8  # 4 bytes type + 4 bytes length
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB max payload
    
    @staticmethod
    def encode_message(msg_type: MessageType, payload: bytes) -> bytes:
        """
        Encode a message with type header.
        
        Args:
            msg_type: Message type
            payload: Message payload (bytes)
            
        Returns:
            Encoded message: [type:4][length:4][payload]
        """
        if len(payload) > Protocol.MAX_MESSAGE_SIZE:
            raise ValueError(f"Payload too large: {len(payload)} > {Protocol.MAX_MESSAGE_SIZE}")
        
        header = struct.pack('!II', int(msg_type), len(payload))
        return header + payload
    
    @staticmethod
    def decode_message(data: bytes) -> Tuple[MessageType, bytes]:
        """
        Decode a message with type header.
        
        Args:
            data: Complete encoded message
            
        Returns:
            (message_type, payload)
        """
        if len(data) < Protocol.HEADER_SIZE:
            raise ValueError("Message too small for header")
        
        msg_type, length = struct.unpack('!II', data[:Protocol.HEADER_SIZE])
        payload = data[Protocol.HEADER_SIZE:]
        
        if len(payload) != length:
            raise ValueError(f"Payload size mismatch: expected {length}, got {len(payload)}")
        
        return MessageType(msg_type), payload
    
    @staticmethod
    def serialize_key_exchange(pub_key_x: int, pub_key_y: int, client_id: str) -> bytes:
        """
        Serialize a key exchange message.
        
        Args:
            pub_key_x: Public key x-coordinate
            pub_key_y: Public key y-coordinate
            client_id: Client identifier
            
        Returns:
            JSON encoded bytes
        """
        data = {
            'pub_key_x': pub_key_x,
            'pub_key_y': pub_key_y,
            'client_id': client_id
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_key_exchange(payload: bytes) -> dict:
        """
        Deserialize a key exchange message.
        
        Returns:
            Dictionary with pub_key_x, pub_key_y, client_id
        """
        return json.loads(payload.decode('utf-8'))
    
    @staticmethod
    def serialize_secure_message(
        encrypted_key: bytes,
        iv: bytes,
        ciphertext: bytes,
        auth_tag: bytes,
        sender_id: str
    ) -> bytes:
        """
        Serialize a secure encrypted message.
        
        Args:
            encrypted_key: Encrypted session key (base64)
            iv: Initialization vector (base64)
            ciphertext: Encrypted message (base64)
            auth_tag: Authentication tag (base64)
            sender_id: Sender identifier
            
        Returns:
            JSON encoded bytes
        """
        import base64
        data = {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
            'sender_id': sender_id
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_secure_message(payload: bytes) -> dict:
        """
        Deserialize a secure encrypted message.
        
        Returns:
            Dictionary with encrypted_key, iv, ciphertext, auth_tag, sender_id (all as bytes)
        """
        import base64
        data = json.loads(payload.decode('utf-8'))
        return {
            'encrypted_key': base64.b64decode(data['encrypted_key']),
            'iv': base64.b64decode(data['iv']),
            'ciphertext': base64.b64decode(data['ciphertext']),
            'auth_tag': base64.b64decode(data['auth_tag']),
            'sender_id': data['sender_id']
        }
    
    @staticmethod
    def serialize_ack(status: str, message: str = "") -> bytes:
        """
        Serialize an acknowledgment message.
        
        Args:
            status: "success" or "failure"
            message: Optional status message
            
        Returns:
            JSON encoded bytes
        """
        data = {'status': status, 'message': message}
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_ack(payload: bytes) -> dict:
        """
        Deserialize an acknowledgment message.
        
        Returns:
            Dictionary with status and message
        """
        return json.loads(payload.decode('utf-8'))
    
    @staticmethod
    def serialize_error(error: str) -> bytes:
        """
        Serialize an error message.
        
        Args:
            error: Error description
            
        Returns:
            JSON encoded bytes
        """
        data = {'error': error}
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_error(payload: bytes) -> str:
        """
        Deserialize an error message.
        
        Returns:
            Error string
        """
        data = json.loads(payload.decode('utf-8'))
        return data.get('error', 'Unknown error')
    
    @staticmethod
    def serialize_auth_register(username: str, password: str) -> bytes:
        """
        Serialize a registration request.
        
        Args:
            username: Username to register
            password: Plain text password (will be hashed on server)
            
        Returns:
            JSON encoded bytes
        """
        data = {'username': username, 'password': password}
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_auth_register(payload: bytes) -> dict:
        """
        Deserialize a registration request.
        
        Returns:
            Dictionary with username and password
        """
        return json.loads(payload.decode('utf-8'))
    
    @staticmethod
    def serialize_auth_login(username: str, password: str) -> bytes:
        """
        Serialize a login request.
        
        Args:
            username: Username
            password: Plain text password
            
        Returns:
            JSON encoded bytes
        """
        data = {'username': username, 'password': password}
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_auth_login(payload: bytes) -> dict:
        """
        Deserialize a login request.
        
        Returns:
            Dictionary with username and password
        """
        return json.loads(payload.decode('utf-8'))
    
    @staticmethod
    def serialize_auth_response(success: bool, message: str, username: str = "") -> bytes:
        """
        Serialize an authentication response.
        
        Args:
            success: Whether authentication succeeded
            message: Status message
            username: Username (if successful)
            
        Returns:
            JSON encoded bytes
        """
        data = {
            'success': success,
            'message': message,
            'username': username
        }
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def deserialize_auth_response(payload: bytes) -> dict:
        """
        Deserialize an authentication response.
        
        Returns:
            Dictionary with success, message, and username
        """
        return json.loads(payload.decode('utf-8'))