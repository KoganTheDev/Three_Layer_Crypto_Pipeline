"""
User Authentication Module - Secure password hashing and verification.

This module provides secure user authentication with:
- Password hashing using bcrypt (industry standard)
- Secure password verification
- User credential validation
- Salt generation and management

Security Features:
- bcrypt automatically handles salt generation
- Password hashing is intentionally slow (prevents brute force)
- Constant-time comparison for password verification
- No plaintext password storage

Usage:
    auth = UserAuthenticator()
    
    # Register new user
    hashed_pw = auth.hash_password("my_password")
    
    # Verify login
    is_valid = auth.verify_password("my_password", hashed_pw)
"""

import bcrypt
import re
from typing import Optional, Tuple


class UserAuthenticator:
    """
    Handles secure password hashing and verification.
    
    Uses bcrypt for password hashing which automatically:
    - Generates unique salts per password
    - Uses adaptive hashing (configurable work factor)
    - Provides constant-time comparison
    """
    
    # bcrypt work factor (higher = more secure but slower)
    # 12 is recommended as of 2024 (takes ~0.3 seconds)
    BCRYPT_ROUNDS = 12
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 32
    
    def __init__(self, bcrypt_rounds: int = BCRYPT_ROUNDS):
        """
        Initialize authenticator.
        
        Args:
            bcrypt_rounds: Work factor for bcrypt (default: 12)
        """
        self.bcrypt_rounds = bcrypt_rounds
    
    def hash_password(self, password: str) -> bytes:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            bytes: Hashed password (includes salt)
            
        Raises:
            ValueError: If password doesn't meet requirements
            
        Example:
            >>> auth = UserAuthenticator()
            >>> hashed = auth.hash_password("my_secure_password")
            >>> print(hashed)
            b'$2b$12$...'  # 60-byte bcrypt hash
        """
        # Validate password
        self._validate_password(password)
        
        # Convert to bytes
        password_bytes = password.encode('utf-8')
        
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        return hashed
    
    def verify_password(self, password: str, hashed_password: bytes) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Previously hashed password
            
        Returns:
            bool: True if password matches, False otherwise
            
        Example:
            >>> auth = UserAuthenticator()
            >>> hashed = auth.hash_password("correct_password")
            >>> auth.verify_password("correct_password", hashed)
            True
            >>> auth.verify_password("wrong_password", hashed)
            False
        """
        try:
            password_bytes = password.encode('utf-8')
            return bcrypt.checkpw(password_bytes, hashed_password)
        except Exception:
            return False
    
    def validate_username(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Validate username format.
        
        Requirements:
        - Length: 3-32 characters
        - Characters: alphanumeric, underscore, hyphen only
        - Must start with letter or number
        
        Args:
            username: Username to validate
            
        Returns:
            Tuple of (is_valid, error_message)
            
        Example:
            >>> auth = UserAuthenticator()
            >>> valid, error = auth.validate_username("user123")
            >>> print(valid)
            True
        """
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < self.MIN_USERNAME_LENGTH:
            return False, f"Username must be at least {self.MIN_USERNAME_LENGTH} characters"
        
        if len(username) > self.MAX_USERNAME_LENGTH:
            return False, f"Username must be at most {self.MAX_USERNAME_LENGTH} characters"
        
        # Check valid characters (alphanumeric, underscore, hyphen)
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', username):
            return False, "Username must start with letter/number and contain only letters, numbers, underscore, or hyphen"
        
        return True, None
    
    def validate_password_strength(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password strength.
        
        Requirements:
        - Length: 8-128 characters
        - Must contain at least one uppercase letter
        - Must contain at least one lowercase letter
        - Must contain at least one digit
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters"
        
        if len(password) > self.MAX_PASSWORD_LENGTH:
            return False, f"Password must be at most {self.MAX_PASSWORD_LENGTH} characters"
        
        # Check for uppercase
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        # Check for lowercase
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        # Check for digit
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        return True, None
    
    def _validate_password(self, password: str) -> None:
        """
        Internal password validation (raises exceptions).
        
        Args:
            password: Password to validate
            
        Raises:
            ValueError: If password doesn't meet requirements
        """
        is_valid, error = self.validate_password_strength(password)
        if not is_valid:
            raise ValueError(error)


class User:
    """
    User data class.
    
    Represents a user with hashed credentials.
    """
    
    def __init__(self, username: str, hashed_password: bytes, 
                 public_key_x: Optional[int] = None, 
                 public_key_y: Optional[int] = None):
        """
        Initialize user.
        
        Args:
            username: User's username
            hashed_password: bcrypt hashed password
            public_key_x: EC public key x-coordinate (optional)
            public_key_y: EC public key y-coordinate (optional)
        """
        self.username = username
        self.hashed_password = hashed_password
        self.public_key_x = public_key_x
        self.public_key_y = public_key_y
    
    def to_dict(self) -> dict:
        """
        Convert user to dictionary for serialization.
        
        Returns:
            Dictionary with user data
        """
        import base64
        return {
            'username': self.username,
            'hashed_password': base64.b64encode(self.hashed_password).decode('utf-8'),
            'public_key_x': self.public_key_x,
            'public_key_y': self.public_key_y
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'User':
        """
        Create user from dictionary.
        
        Args:
            data: Dictionary with user data
            
        Returns:
            User instance
        """
        import base64
        return cls(
            username=data['username'],
            hashed_password=base64.b64decode(data['hashed_password']),
            public_key_x=data.get('public_key_x'),
            public_key_y=data.get('public_key_y')
        )


__all__ = ['UserAuthenticator', 'User']
