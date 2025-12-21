import os
from cryptography.hazmat.primitives import hashes
from utils.signature_object import SignatureObject
from utils.utils import ec_scalar_mult, ec_point_add
import common.constants as const

"""
Schnorr Signature Algorithm Implementation

The Schnorr signature is a digital signature scheme based on elliptic curve cryptography.

Key Properties:
- Linear signing equation (simpler than ECDSA)
- Non-malleable (can't modify valid signature to create another valid one)
- Deterministic when k is deterministic
- Provably secure under discrete log assumption
"""

"""
- p: Field prime (defines the finite field)
- n: Order of generator G (number of points before cycling)
- G: Base point generator (public reference point)
"""

class SchnorrSigner:
    
    def generate_signature(self, data: bytes, private_key) -> SignatureObject:
        """
        Generate a Schnorr signature for the given data.
        
        Args:
            data: E-Mail bytes to sign
            private_key: Cryptography EC private key object
            
        Returns:
            SignatureObject containing (r, s) bytes
            
        Process:
            1. Extract private scalar d from key
            2. Generate random nonce k
            3. Compute point R = k*G on curve
            4. Hash r-coordinate with message to get challenge e
            5. Solve s = k + e*d (mod n)
        """
        d = private_key.private_numbers().private_value
        k = int.from_bytes(os.urandom(32), 'big') % (const._n - 1) + 1
        G = (const._Gx, const._Gy)
        R = ec_scalar_mult(k, G, const._p)
        
        r = R[0].to_bytes(32, 'big')
        hash_obj = hashes.Hash(hashes.SHA256())
        hash_obj.update(r + data)
        e = int.from_bytes(hash_obj.finalize(), 'big') % const._n
        s = (k + e * d) % const._n
        
        return SignatureObject(r, s.to_bytes(32, 'big'))

    def verify_signature(self, data: bytes, signature: SignatureObject, public_key) -> bool:
        """
        Verify a Schnorr signature.
        
        Args:
            data: Original message bytes
            signature: SignatureObject with (r, s)
            public_key: Cryptography EC public key object
            
        Returns:
            True if signature is valid, False otherwise
            
        Process:
            1. Recompute challenge e = H(r || m) mod n
            2. Verify the equation: sG - eQ = R
            3. Check if x-coordinate of result equals r
        """
        try:
            r = signature.get_r()
            s = int.from_bytes(signature.get_s(), 'big')
            
            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(r + data)
            e = int.from_bytes(hash_obj.finalize(), 'big') % const._n
            
            G = (const._Gx, const._Gy)
            Q = (public_key.public_numbers().x, public_key.public_numbers().y)
            
            sG = ec_scalar_mult(s, G, const._p)
            eQ = ec_scalar_mult(e, Q, const._p)
            eQ_neg = (eQ[0], (-eQ[1]) % const._p) if eQ else None
            R_prime = ec_point_add(sG, eQ_neg, const._p)
            
            return R_prime[0].to_bytes(32, 'big') == r if R_prime else False
        except:
            return False

