from diffie_hellman import DiffieHellman
from Crypto.Cipher import AES
from random import getrandbits
from binascii import unhexlify
import hashlib


def generateHash(data):
    return hashlib.sha1(str(data).encode('UTF-8')).hexdigest()

def encrypt_aes(session_key, msg):
    aes_key = unhexlify(generateHash(session_key))[:16]
    iv = getrandbits(128).to_bytes(16, 'big')
    aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    encrypted_msg = aes.encrypt(msg)
    return encrypted_msg, iv

def decrypt_aes(session_key, iv, msg):
    aes_key = unhexlify(generateHash(session_key))[:16]
    aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_msg = aes.decrypt(msg)
    return decrypted_msg

# A -> B
# Send "p", "g", "A"
p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        'fffffffffffff', 16)
g = 2
alice = DiffieHellman(g, p)
alice.generate_private_key()
alice.generate_public_key()

# B -> A
# Send "B"
bob = DiffieHellman(g, p)
bob.generate_private_key()
bob.generate_public_key()
bob.generate_session_key(alice.public_key)

# A -> B
# Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
alice.generate_session_key(bob.public_key)
alice_msg = "Hello, Bob! It's Alice".encode()[:16]
alice_encrypted_msg, alice_iv = encrypt_aes(alice.session_key, alice_msg)

# B -> A
# Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
bob_msg = decrypt_aes(bob.session_key, alice_iv, alice_encrypted_msg)
bob_encrypted_msg, bob_iv = encrypt_aes(bob.session_key, bob_msg)

#
# A checks messages
alice_decrypted_msg = decrypt_aes(alice.session_key, bob_iv, bob_encrypted_msg)
if alice_msg == alice_decrypted_msg:
    print("alice_msg == alice_decrypted_msg == {}".format(alice_msg))

##############




