from . import algo
from .utils import decode_string


class SignatureHandlers:
    def __init__(self):
        self._classes = {}

    def add_key_type(self, key_type: str, signer, verifier):
        self._classes[key_type] = (signer, verifier)

    def supports(self, key_type: str):
        return key_type in self._classes

    def get_supported(self):
        return self._classes.keys()

    def create_signer(self, key_type, secret, secret_format=None):
        if secret and secret_format:
            secret = decode_string(secret, secret_format)
        return self._classes[key_type][0](key_type, secret)

    def create_verifier(self, key_type, pubkey, pubkey_format=None):
        if pubkey and pubkey_format:
            pubkey = decode_string(pubkey, pubkey_format)
        return self._classes[key_type][1](key_type, pubkey)


ALL = SignatureHandlers()

if algo.ed25519:
    ALL.add_key_type('ed25519', algo.ed25519.Signer, algo.ed25519.Verifier)
if algo.rsa:
    ALL.add_key_type('rsa', algo.rsa.Signer, algo.rsa.Verifier)
    ALL.add_key_type('rsa-sha256', algo.rsa.Signer, algo.rsa.Verifier)
if algo.secp256k1:
    ALL.add_key_type('secp256k1', algo.secp256k1.Signer, algo.secp256k1.Verifier)
