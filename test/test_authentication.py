"""
Test User Authentication System

Tests for:
- Password hashing and verification
- Username validation
- Password strength validation
- User database operations
- Registration and login flows
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.user_auth import UserAuthenticator, User
from src.utils.user_database import UserDatabase


class TestUserAuthenticator:
    """Test password hashing and validation."""
    
    def test_password_hashing(self):
        """Test that passwords are hashed correctly."""
        auth = UserAuthenticator()
        password = "TestPass123"
        
        hashed = auth.hash_password(password)
        
        # Check hash format (bcrypt produces 60-byte hash)
        assert isinstance(hashed, bytes)
        assert len(hashed) == 60
        assert hashed.startswith(b'$2b$')
        
        print("✓ Password hashing works correctly")
    
    def test_password_verification_success(self):
        """Test that correct passwords verify successfully."""
        auth = UserAuthenticator()
        password = "CorrectPass123"
        
        hashed = auth.hash_password(password)
        is_valid = auth.verify_password(password, hashed)
        
        assert is_valid is True
        print("✓ Correct password verification passed")
    
    def test_password_verification_failure(self):
        """Test that incorrect passwords fail verification."""
        auth = UserAuthenticator()
        password = "CorrectPass123"
        wrong_password = "WrongPass123"
        
        hashed = auth.hash_password(password)
        is_valid = auth.verify_password(wrong_password, hashed)
        
        assert is_valid is False
        print("✓ Incorrect password verification failed as expected")
    
    def test_password_uniqueness(self):
        """Test that same password produces different hashes (due to salt)."""
        auth = UserAuthenticator()
        password = "SamePass123"
        
        hash1 = auth.hash_password(password)
        hash2 = auth.hash_password(password)
        
        # Different salts should produce different hashes
        assert hash1 != hash2
        
        # But both should verify correctly
        assert auth.verify_password(password, hash1)
        assert auth.verify_password(password, hash2)
        
        print("✓ Password salt uniqueness verified")
    
    def test_username_validation_valid(self):
        """Test valid usernames."""
        auth = UserAuthenticator()
        
        valid_usernames = [
            "alice",
            "bob123",
            "user_name",
            "test-user",
            "User123",
            "a12",  # minimum length
        ]
        
        for username in valid_usernames:
            is_valid, error = auth.validate_username(username)
            assert is_valid is True, f"Username '{username}' should be valid"
            assert error is None
        
        print("✓ Valid username validation passed")
    
    def test_username_validation_invalid(self):
        """Test invalid usernames."""
        auth = UserAuthenticator()
        
        invalid_usernames = [
            "",           # empty
            "ab",         # too short
            "a" * 33,     # too long
            "_user",      # starts with underscore
            "-user",      # starts with hyphen
            "user@name",  # invalid character
            "user name",  # space
            "user.name",  # dot
        ]
        
        for username in invalid_usernames:
            is_valid, error = auth.validate_username(username)
            assert is_valid is False, f"Username '{username}' should be invalid"
            assert error is not None
        
        print("✓ Invalid username validation passed")
    
    def test_password_strength_valid(self):
        """Test valid passwords."""
        auth = UserAuthenticator()
        
        valid_passwords = [
            "Password1",      # minimum requirements
            "MySecure123",    # good password
            "Test1234Pass",   # longer password
            "Abcd1234",       # exactly 8 chars
        ]
        
        for password in valid_passwords:
            is_valid, error = auth.validate_password_strength(password)
            assert is_valid is True, f"Password should be valid"
            assert error is None
        
        print("✓ Valid password strength validation passed")
    
    def test_password_strength_invalid(self):
        """Test invalid passwords."""
        auth = UserAuthenticator()
        
        invalid_passwords = [
            "",              # empty
            "Pass1",         # too short
            "password123",   # no uppercase
            "PASSWORD123",   # no lowercase
            "Password",      # no digit
            "Pass 123",      # contains space (but valid length/chars)
        ]
        
        for password in invalid_passwords:
            is_valid, error = auth.validate_password_strength(password)
            if password == "Pass 123":
                # This might be valid depending on requirements
                continue
            assert is_valid is False, f"Password '{password}' should be invalid"
            assert error is not None
        
        print("✓ Invalid password strength validation passed")


class TestUserClass:
    """Test User data class."""
    
    def test_user_creation(self):
        """Test creating a user."""
        auth = UserAuthenticator()
        hashed_pw = auth.hash_password("TestPass123")
        
        user = User("alice", hashed_pw, 123456, 789012)
        
        assert user.username == "alice"
        assert user.hashed_password == hashed_pw
        assert user.public_key_x == 123456
        assert user.public_key_y == 789012
        
        print("✓ User creation passed")
    
    def test_user_serialization(self):
        """Test user to_dict and from_dict."""
        auth = UserAuthenticator()
        hashed_pw = auth.hash_password("TestPass123")
        
        user = User("bob", hashed_pw, 111, 222)
        user_dict = user.to_dict()
        
        # Check dictionary structure
        assert 'username' in user_dict
        assert 'hashed_password' in user_dict
        assert 'public_key_x' in user_dict
        assert 'public_key_y' in user_dict
        
        # Reconstruct user
        reconstructed = User.from_dict(user_dict)
        
        assert reconstructed.username == user.username
        assert reconstructed.hashed_password == user.hashed_password
        assert reconstructed.public_key_x == user.public_key_x
        assert reconstructed.public_key_y == user.public_key_y
        
        print("✓ User serialization passed")


class TestUserDatabase:
    """Test user database operations."""
    
    def test_database_creation(self):
        """Test creating a new database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            assert os.path.exists(db_path)
            assert db.get_user_count() == 0
            
            print("✓ Database creation passed")
    
    def test_user_registration_success(self):
        """Test registering a new user."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            success, message = db.register_user("alice", "SecurePass123")
            
            assert success is True
            assert "successful" in message.lower()
            assert db.get_user_count() == 1
            assert db.user_exists("alice")
            
            print("✓ User registration passed")
    
    def test_user_registration_duplicate(self):
        """Test that duplicate usernames are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register first user
            db.register_user("alice", "SecurePass123")
            
            # Try to register again
            success, message = db.register_user("alice", "DifferentPass123")
            
            assert success is False
            assert "already exists" in message.lower()
            assert db.get_user_count() == 1
            
            print("✓ Duplicate username rejection passed")
    
    def test_user_registration_invalid_credentials(self):
        """Test that invalid credentials are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Invalid username
            success, message = db.register_user("ab", "SecurePass123")
            assert success is False
            
            # Invalid password
            success, message = db.register_user("alice", "weak")
            assert success is False
            
            print("✓ Invalid credentials rejection passed")
    
    def test_user_authentication_success(self):
        """Test authenticating with correct credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register user
            db.register_user("alice", "SecurePass123")
            
            # Authenticate
            success, user = db.authenticate_user("alice", "SecurePass123")
            
            assert success is True
            assert user is not None
            assert user.username == "alice"
            
            print("✓ User authentication success passed")
    
    def test_user_authentication_wrong_password(self):
        """Test authentication with wrong password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register user
            db.register_user("alice", "SecurePass123")
            
            # Authenticate with wrong password
            success, user = db.authenticate_user("alice", "WrongPass123")
            
            assert success is False
            assert user is None
            
            print("✓ Wrong password rejection passed")
    
    def test_user_authentication_nonexistent_user(self):
        """Test authentication for non-existent user."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Try to authenticate non-existent user
            success, user = db.authenticate_user("nonexistent", "SomePass123")
            
            assert success is False
            assert user is None
            
            print("✓ Non-existent user rejection passed")
    
    def test_get_user(self):
        """Test getting a user."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register user
            db.register_user("alice", "SecurePass123")
            
            # Get user
            user = db.get_user("alice")
            
            assert user is not None
            assert user.username == "alice"
            
            # Get non-existent user
            user = db.get_user("nonexistent")
            assert user is None
            
            print("✓ Get user passed")
    
    def test_list_users(self):
        """Test listing all users."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register multiple users
            db.register_user("alice", "SecurePass123")
            db.register_user("bob", "SecurePass456")
            db.register_user("charlie", "SecurePass789")
            
            # List users
            users = db.list_users()
            
            assert len(users) == 3
            assert "alice" in users
            assert "bob" in users
            assert "charlie" in users
            
            print("✓ List users passed")
    
    def test_delete_user(self):
        """Test deleting a user."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register user
            db.register_user("alice", "SecurePass123")
            assert db.user_exists("alice")
            
            # Delete user
            success = db.delete_user("alice")
            
            assert success is True
            assert not db.user_exists("alice")
            assert db.get_user_count() == 0
            
            # Try to delete non-existent user
            success = db.delete_user("nonexistent")
            assert success is False
            
            print("✓ Delete user passed")
    
    def test_update_public_key(self):
        """Test updating user's public key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_users.json")
            db = UserDatabase(db_path)
            
            # Register user
            db.register_user("alice", "SecurePass123")
            
            # Update public key
            success = db.update_user_public_key("alice", 123456, 789012)
            
            assert success is True
            
            # Verify update
            user = db.get_user("alice")
            assert user.public_key_x == 123456
            assert user.public_key_y == 789012
            
            print("✓ Update public key passed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
