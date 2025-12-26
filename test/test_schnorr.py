"""
Test module for Schnorr signature implementation.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from src.algorithms.schnorr.schnorr_signature import SchnorrSigner
from src.utils.signature_object import SignatureObject
from src.utils.key_pair import KeyPair


class TestSchnorrSigner:
    """Test cases for SchnorrSigner class."""
    
    @pytest.fixture
    def signer(self):
        """Create a SchnorrSigner instance."""
        return SchnorrSigner()
    
    @pytest.fixture
    def key_pair(self):
        """Generate a key pair for testing."""
        return KeyPair.generate()
    
    def test_signer_initialization(self, signer):
        """Test that signer initializes correctly."""
        assert signer is not None
    
    def test_signature_generation(self, signer, key_pair):
        """Test that signature generation produces a valid SignatureObject."""
        private_key, public_key = key_pair
        message = b"Test message for Schnorr signature"
        
        signature = signer.generate_signature(message, private_key)
        
        assert isinstance(signature, SignatureObject)
        assert signature.get_r() is not None
        assert signature.get_s() is not None
        assert len(signature.get_r()) == 32
        assert len(signature.get_s()) == 32
    
    def test_signature_verification_valid(self, signer, key_pair):
        """Test that a valid signature verifies correctly."""
        private_key, public_key = key_pair
        message = b"Test message for Schnorr signature"
        
        # Generate signature
        signature = signer.generate_signature(message, private_key)
        
        # Verify signature
        is_valid = signer.verify_signature(message, signature, public_key)
        assert is_valid is True
    
    def test_signature_verification_invalid_message(self, signer, key_pair):
        """Test that signature fails for different message."""
        private_key, public_key = key_pair
        message = b"Original message"
        different_message = b"Different message"
        
        # Generate signature for original message
        signature = signer.generate_signature(message, private_key)
        
        # Try to verify with different message
        is_valid = signer.verify_signature(different_message, signature, public_key)
        assert is_valid is False
    
    def test_signature_verification_wrong_key(self, signer):
        """Test that signature fails with wrong public key."""
        private_key1, public_key1 = KeyPair.generate()
        private_key2, public_key2 = KeyPair.generate()
        message = b"Test message"
        
        # Generate signature with private_key1
        signature = signer.generate_signature(message, private_key1)
        
        # Try to verify with public_key2 (from different key pair)
        is_valid = signer.verify_signature(message, signature, public_key2)
        assert is_valid is False
    
    def test_multiple_signatures_different(self, signer, key_pair):
        """Test that multiple signatures for same message are different (randomness)."""
        private_key, public_key = key_pair
        message = b"Same message"
        
        signature1 = signer.generate_signature(message, private_key)
        signature2 = signer.generate_signature(message, private_key)
        
        # Signatures should be different due to random k
        # (They will have different s values since k is random)
        assert signature1.get_s() != signature2.get_s()
        
        # But both should verify
        assert signer.verify_signature(message, signature1, public_key)
        assert signer.verify_signature(message, signature2, public_key)
    
    def test_signature_to_bytes_and_from_bytes(self, signer, key_pair):
        """Test SignatureObject serialization."""
        private_key, public_key = key_pair
        message = b"Test serialization"
        
        signature = signer.generate_signature(message, private_key)
        
        # Convert to bytes and back
        sig_bytes = signature.to_bytes()
        assert len(sig_bytes) == 64
        
        signature_restored = SignatureObject.from_bytes(sig_bytes)
        
        # Restored signature should also verify
        assert signer.verify_signature(message, signature_restored, public_key)
    
    def test_hash_function(self):
        """Test that hash function is deterministic."""
        from cryptography.hazmat.primitives import hashes
        
        data1 = b"test data"
        data2 = b"test data"
        data3 = b"different data"
        
        hash_obj1 = hashes.Hash(hashes.SHA256())
        hash_obj1.update(data1)
        hash1 = hash_obj1.finalize()
        
        hash_obj2 = hashes.Hash(hashes.SHA256())
        hash_obj2.update(data2)
        hash2 = hash_obj2.finalize()
        
        hash_obj3 = hashes.Hash(hashes.SHA256())
        hash_obj3.update(data3)
        hash3 = hash_obj3.finalize()
        
        # Same input should produce same hash
        assert hash1 == hash2
        
        # Different input should produce different hash
        assert hash1 != hash3
        
        # Hash should be 32 bytes (SHA256)
        assert len(hash1) == 32
    
    def test_empty_message(self, signer, key_pair):
        """Test signing and verifying empty message."""
        private_key, public_key = key_pair
        message = b""
        
        signature = signer.generate_signature(message, private_key)
        is_valid = signer.verify_signature(message, signature, public_key)
        
        assert is_valid is True
    
    def test_long_message(self, signer, key_pair):
        """Test signing and verifying long message."""
        private_key, public_key = key_pair
        message = b"A" * 10000
        
        signature = signer.generate_signature(message, private_key)
        is_valid = signer.verify_signature(message, signature, public_key)
        
        assert is_valid is True
    
    def test_invalid_signature_object(self, signer, key_pair):
        """Test verification with invalid signature format."""
        private_key, public_key = key_pair
        message = b"Test message"
        
        # Create invalid signature (wrong length)
        invalid_sig = SignatureObject(b"short", b"short")
        
        is_valid = signer.verify_signature(message, invalid_sig, public_key)
        assert is_valid is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
