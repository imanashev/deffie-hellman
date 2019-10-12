from cryptopals33.diffie_hellman import DiffieHellman
import aes


if __name__ == "__main__":
    # A->M
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

    # M->B
    # Send "p", "g", "p"
    # B->M
    # Send "B"
    bob = DiffieHellman(g, p)
    bob.generate_private_key()
    bob.generate_public_key()
    bob.generate_session_key(p)

    # M->A
    # Send "p"
    # A->M
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    # M->B
    # Relay that to B
    alice.generate_session_key(p)
    alice_msg = "Hello, Bob! It's Alice".encode()[:16]
    alice_encrypted_msg, alice_iv = aes.encrypt(alice.session_key, alice_msg)

    # B->M
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    bob_msg = aes.decrypt(bob.session_key, alice_iv, alice_encrypted_msg)
    bob_encrypted_msg, bob_iv = aes.encrypt(bob.session_key, bob_msg)

    # M->A
    # Relay that to A
    eva_msg = aes.decrypt(0, alice_iv, alice_encrypted_msg)

    #########
    print(eva_msg)
    if alice_msg == bob_msg == eva_msg:
        print("GOOD: alice_msg == bob_msg == eva_msg == {}".format(alice_msg))
    else:
        print("BAD")
