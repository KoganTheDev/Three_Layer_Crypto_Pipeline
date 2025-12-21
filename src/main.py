from utils.key_pair import KeyPair
import exchange_manager as exchange_manager


def main():
    
    # Generate keys for sender and recipient
    sender_keys = KeyPair.generate()
    recipient_keys = KeyPair.generate()

    # Pass them into the manager
    manager = exchange_manager.ExchangeManager(      
        sender_private_key = sender_keys[0], # Get SENDER_PRIVATE key
        recipient_public_key=recipient_keys[1] # GET RECIPIENT PUBLIC key
    )
    
    

if __name__ == "__main__":
    main()