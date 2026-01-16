"""
User Database - Secure storage for user credentials.

This module provides persistent storage for user accounts with:
- JSON-based storage (can be upgraded to SQLite)
- Thread-safe operations
- Automatic file creation and backups
- User CRUD operations

Security:
- Passwords are stored as bcrypt hashes (never plaintext)
- File permissions should be restricted (600 on Unix)
- Database file is in .gitignore by default

Usage:
    db = UserDatabase("users.json")
    
    # Register user
    success, msg = db.register_user("alice", hashed_password)
    
    # Get user
    user = db.get_user("alice")
    
    # List all users
    users = db.list_users()
"""

import json
import os
import threading
from typing import Optional, List, Tuple
from pathlib import Path

from src.utils.user_auth import User, UserAuthenticator


class UserDatabase:
    """
    Manages persistent storage of user accounts.
    
    Thread-safe JSON-based database for user credentials.
    """
    
    def __init__(self, db_path: str = "data/users.json"):
        """
        Initialize user database.
        
        Args:
            db_path: Path to database file (default: data/users.json)
        """
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self.authenticator = UserAuthenticator()
        
        # Create data directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database file if it doesn't exist
        if not self.db_path.exists():
            self._save_database({})
    
    def _load_database(self) -> dict:
        """
        Load database from file.
        
        Returns:
            Dictionary of username -> user data
        """
        try:
            with open(self.db_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_database(self, data: dict) -> None:
        """
        Save database to file.
        
        Args:
            data: Dictionary of username -> user data
        """
        # Create backup first
        if self.db_path.exists():
            backup_path = self.db_path.with_suffix('.json.bak')
            try:
                import shutil
                shutil.copy2(self.db_path, backup_path)
            except Exception:
                pass  # Backup failed, but continue
        
        # Write to file
        with open(self.db_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Set restrictive permissions on Unix systems
        try:
            os.chmod(self.db_path, 0o600)
        except Exception:
            pass  # Windows doesn't support chmod
    
    def register_user(self, username: str, password: str, 
                     public_key_x: Optional[int] = None,
                     public_key_y: Optional[int] = None) -> Tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            username: Unique username
            password: Plain text password (will be hashed)
            public_key_x: EC public key x-coordinate (optional)
            public_key_y: EC public key y-coordinate (optional)
            
        Returns:
            Tuple of (success, message)
            
        Example:
            >>> db = UserDatabase()
            >>> success, msg = db.register_user("alice", "SecurePass123")
            >>> print(success, msg)
            True, "User registered successfully"
        """
        with self.lock:
            # Validate username
            is_valid, error = self.authenticator.validate_username(username)
            if not is_valid:
                return False, error
            
            # Validate password
            is_valid, error = self.authenticator.validate_password_strength(password)
            if not is_valid:
                return False, error
            
            # Load database
            db = self._load_database()
            
            # Check if user already exists
            if username in db:
                return False, "Username already exists"
            
            # Hash password
            hashed_password = self.authenticator.hash_password(password)
            
            # Create user
            user = User(username, hashed_password, public_key_x, public_key_y)
            
            # Save to database
            db[username] = user.to_dict()
            self._save_database(db)
            
            return True, "User registered successfully"
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[User]]:
        """
        Authenticate a user.
        
        Args:
            username: Username to authenticate
            password: Plain text password to verify
            
        Returns:
            Tuple of (success, user_object or None)
            
        Example:
            >>> db = UserDatabase()
            >>> success, user = db.authenticate_user("alice", "SecurePass123")
            >>> if success:
            ...     print(f"Welcome, {user.username}!")
        """
        with self.lock:
            # Load database
            db = self._load_database()
            
            # Check if user exists
            if username not in db:
                return False, None
            
            # Get user
            user = User.from_dict(db[username])
            
            # Verify password
            if self.authenticator.verify_password(password, user.hashed_password):
                return True, user
            else:
                return False, None
    
    def get_user(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username to retrieve
            
        Returns:
            User object or None if not found
        """
        with self.lock:
            db = self._load_database()
            
            if username not in db:
                return None
            
            return User.from_dict(db[username])
    
    def user_exists(self, username: str) -> bool:
        """
        Check if user exists.
        
        Args:
            username: Username to check
            
        Returns:
            True if user exists, False otherwise
        """
        with self.lock:
            db = self._load_database()
            return username in db
    
    def update_user_public_key(self, username: str, 
                               public_key_x: int, 
                               public_key_y: int) -> bool:
        """
        Update user's public key.
        
        Args:
            username: Username to update
            public_key_x: EC public key x-coordinate
            public_key_y: EC public key y-coordinate
            
        Returns:
            True if successful, False otherwise
        """
        with self.lock:
            db = self._load_database()
            
            if username not in db:
                return False
            
            db[username]['public_key_x'] = public_key_x
            db[username]['public_key_y'] = public_key_y
            
            self._save_database(db)
            return True
    
    def delete_user(self, username: str) -> bool:
        """
        Delete a user.
        
        Args:
            username: Username to delete
            
        Returns:
            True if successful, False if user not found
        """
        with self.lock:
            db = self._load_database()
            
            if username not in db:
                return False
            
            del db[username]
            self._save_database(db)
            return True
    
    def list_users(self) -> List[str]:
        """
        List all usernames.
        
        Returns:
            List of usernames
        """
        with self.lock:
            db = self._load_database()
            return list(db.keys())
    
    def get_user_count(self) -> int:
        """
        Get total number of users.
        
        Returns:
            Number of registered users
        """
        with self.lock:
            db = self._load_database()
            return len(db)


__all__ = ['UserDatabase']
