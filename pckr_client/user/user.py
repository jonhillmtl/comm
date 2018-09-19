import os
from Crypto.PublicKey import RSA 
from ..utilities import normalize_path

USER_ROOT = "~/pckr/"

class User(object):
    username = None

    def __init__(self, username):
        self.username = username

    @property
    def exists(self):
        return False

    @property
    def path(self):
        return normalize_path(os.path.join(USER_ROOT, self.username))

    @property
    def public_key_text(self):
        return open(self.public_key_path).read()

    @property
    def public_key_path(self):
        return os.path.join(self.path, "public.key")

    @property
    def private_key_path(self):
        return os.path.join(self.path, "private.key")

    @property
    def public_key_responses(self):
        return []

    @property
    def public_key_requests(self):
        return []

    def initiate_rsa(self):
        new_key = RSA.generate(2048, e=65537) 
        with open(self.public_key_path, "wb") as f:
            f.write(new_key.publickey().exportKey("PEM") )

        with open(self.private_key_path, "wb") as f:
            f.write(new_key.exportKey("PEM"))

        return True