from Crypto.Cipher import AES
from random import getrandbits
from binascii import unhexlify
from sha1 import generateHash


def encrypt(session_key, msg):
    aes_key = unhexlify(generateHash(session_key))[:16]
    iv = getrandbits(128).to_bytes(16, 'big')
    aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    encrypted_msg = aes.encrypt(msg)
    return encrypted_msg, iv


def decrypt(session_key, iv, msg):
    aes_key = unhexlify(generateHash(session_key))[:16]
    aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_msg = aes.decrypt(msg)
    return decrypted_msg
