from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
from ECC_post_lectures import EllipticCurve  

class ECCAES:
    def __init__(self, a=None, b=None, p=None, domain_point=None):
        if a is None or b is None or p is None or domain_point is None:
            #NIST P-256 curve parameters if not provided
            p = 2**256 - 2**224 + 2**192 + 2**96 - 1
            a = -3
            b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
            domain_point = (48439561293906451759052585252797914202762949526041747995844080717082404635286,
                            36134250956749795798585127919587881956611106672985015071877198253568414405109)
        #set the curve and leave empty keys
        self.curve = EllipticCurve(a, b, p, domain_point)
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        #generate rand private key within 1 - (p-1)
        #how does priv key size affect curves that can be used? i guess 
        self.private_key = int.from_bytes(urandom(32), 'big') % self.curve.p
        self.public_key = self.curve.gen_pubkey(self.private_key)

    def encrypt(self, plaintext, recipient_public_key):
        #ephemeral key production
        #ephemeral keys are a secondary ecryption that is !random but known! to further obfuscate the ECC encryption
        ephemeral_private_key = int.from_bytes(urandom(32), 'big') % self.curve.p
        ephemeral_public_key = self.curve.gen_pubkey(ephemeral_private_key)

        #diffie hellman, part of x coord, intialisation vector
        shared_secret = self.curve.gen_shared_secret(ephemeral_private_key, recipient_public_key)
        aes_key = shared_secret[0].to_bytes(32, 'big')
        iv = urandom(16)

        #cipher using aes and ssh backend
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        #output all the needed data for decryption
        return (ephemeral_public_key, iv, ciphertext)

    def decrypt(self, encrypted_data):
        ephemeral_public_key, iv, ciphertext = encrypted_data

        shared_secret = self.curve.gen_shared_secret(self.private_key, ephemeral_public_key)
        aes_key = shared_secret[0].to_bytes(32, 'big')
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode()

# Example usage:
if __name__ == "__main__":
    # Create instances for Alice and Bob using default NIST P-256 curve
    alice = ECCAES()
    bob = ECCAES()

    # Generate key pairs
    alice.generate_key_pair()
    bob.generate_key_pair()

    # Alice encrypts a message for Bob
    message = "Hello, Bob! This is a secret message."
    encrypted_data = alice.encrypt(message, bob.public_key)

    # Bob decrypts the message
    decrypted_message = bob.decrypt(encrypted_data)

    print(f"Original message: {message}")
    print(f"Decrypted message: {decrypted_message}")

    # Example with custom curve parameters
    custom_p = 2**255 - 19  # Curve25519 prime
    custom_a = 486662
    custom_b = 1
    custom_domain_point = (9, 14781619447589544791020593568409986887264606134616475288964881837755586237401)

    alice_custom = ECCAES(custom_a, custom_b, custom_p, custom_domain_point)
    bob_custom = ECCAES(custom_a, custom_b, custom_p, custom_domain_point)

    alice_custom.generate_key_pair()
    bob_custom.generate_key_pair()

    custom_message = "Hello, Bob! This is a secret message using a custom curve."
    custom_encrypted_data = alice_custom.encrypt(custom_message, bob_custom.public_key)
    custom_decrypted_message = bob_custom.decrypt(custom_encrypted_data)

    print(f"\nCustom curve - Original message: {custom_message}")
    print(f"Custom curve - Decrypted message: {custom_decrypted_message}")