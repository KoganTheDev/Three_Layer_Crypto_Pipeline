import os
from src.utils.email_message import EmailMessage
from src.utils.secure_bundle import SecureBundle
from src.utils.signature_object import SignatureObject

from cryptography.hazmat.primitives.asymmetric import ec

from src.algorithms.schnorr.schnorr_signature import SchnorrSigner

class ExchangeManager:
    """
    ! ADD DOCS
    This class handles everything in the workflow of the project
    
    """
    
    def __init__(self,
                 sender_private_key: ec.EllipticCurvePrivateKey, 
                 recipient_public_key: ec.EllipticCurvePublicKey) -> None:
        # Long-term keys passed in from main
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        
        # Ephemeral values initialized as None, generated during secure_send
        self.session_key = None
        self.iv = None
        
    
    def generate_session_key(self) -> bytes:
        """Generates a random 256-bit long session key."""
        return os.urandom(32)
    
    def generate_iv(self) -> bytes:
        """Generates a random 96-bit (12-byte) IV for GCM mode."""
        return os.urandom(12)
    
        #! DELETE THE RETURNED NONE when the securedBundle is implemented correctly
    def secure_send(self, mail : EmailMessage) -> SecureBundle | None:
        """
        Send data using Schnorr Signature + RC6 (GCM) Cipher + El-Gamal (EC)
        
        STEPS:
        ------------------YUVAL------------------------
        1. convert mail content to a bytes object
        2. Use Schnorr's algorithm to generate a Signature
        3. Generate a random 256-bit long session key and a 96-bit long nonce (IV)
        
        ------------------NIKO-------------------------
        4. Run RC6 to create the Ciphertext and the Authentication tag
        
        ------------------RONI-------------------------
        5. Create encrypted key on top of the session and recipient's public EC key
        
        return a SecureBundle object which contains the following elements:
        (Encryption Key, Initialization Vector, Ciphertext, Authentication Tag, Sender's EC Public Key)
        """
        
        # Step 1: Convert main content to bytes
        mail_as_bytes = mail.to_bytes()
        
        # Step 2: Run Schnorr's Signature algorithm in order to create the signature
        schnorr_algorithm = SchnorrSigner()     
        signature = schnorr_algorithm.generate_signature(mail_as_bytes, self.sender_private_key)
        
        # Step 3.1 Generate a random 256-bit long session key
        self.session_key = self.generate_session_key()
        
        # Step 3.2 Generate a random 96-bit long IV for GCM
        self.iv = self.generate_iv()
        
        # Step 4: # TODO: Continue here
        
                
        return None
    
    
    def secure_receive(self, bundle : SecureBundle) -> str: #! Maybe return the contents instead aof a boolean
        """
        Unpack the Secure Bundle and get the decipher the contents
        
        STEPS:
        ---------------RONI----------------
        Step 1: Run El-Gamal (EC) Decryption to receive the Session Key (K)
        
        ---------------NIKO----------------
        Step 2: Run RC6 (GCM) to decrypt thet Email (M) and the Signature (S)
                *IMPORTANT: If the Auth Tag doesn't match => Throw an error #? Maybe customized error
                
        ---------------YUVAL---------------
        Step 3: Run Schnorr's algorithm to verify the signature
        
        
        #* RETURN: content if valid otherwise throw error
                
        """
        
        # TODO: Continue here
        
        
        
        
        ###################**PLACEHOLDERS****###############
        email_as_bytes = bytes() # Insert email in bytes form here
        signature = SignatureObject(bytes(), bytes()) # Given from Niko's algorithm
        
        
        ###################################################
        
        
        # Step 3: Using Schnorr's algorithm, verify the contents
        schnorr_algorithm = SchnorrSigner()
        is_signature_verified = schnorr_algorithm.verify_signature(email_as_bytes, signature, bundle.__sender_pub_key)
        
        if (not is_signature_verified): # Schnore fails
            raise Exception("Generic EXCEPTION FOR now")
        
        return email_as_bytes.decode() # Return the E-Mail's contents
        