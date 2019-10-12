import random
from datetime import datetime

class DiffieHellman:
    def __init__(self, g, p):
        self.generator = g
        self.module = p
        self.private_key = None
        self.public_key = None
        self.session_key = None
        random.seed(datetime.now())

    def generate_private_key(self):
        self.private_key = random.randint(0, self.module - 1)

    def generate_public_key(self):
        self.public_key = pow(self.generator, self.private_key, self.module)

    def generate_session_key(self, public_key):
        self.session_key = pow(public_key, self.private_key, self.module)
