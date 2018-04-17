from . import algo
from .utils import decode_string, encode_string


class SignatureHandlers:
    def __init__(self):
        self._classes = {}

    def add_key_type(self, key_type: str, signer, verifier):
        self._classes[key_type] = (signer, verifier)

    def supports(self, key_type: str):
        return key_type in self._classes

    def create_signer(self, key_type, secret, secret_format=None):
        if secret and secret_format:
            secret = decode_string(secret, secret_format)
        return self._classes[key_type][0](key_type, secret)

    def create_verifier(self, key_type, pubkey, pubkey_format=None):
        if pubkey and pubkey_format:
            pubkey = decode_string(pubkey, pubkey_format)
        return self._classes[key_type][1](key_type, pubkey)


ALL = SignatureHandlers()

ALL.add_key_type('ed25519', algo.Ed25519Signer, algo.Ed25519Verifier)
ALL.add_key_type('rsa', algo.RsaSigner, algo.RsaVerifier)
ALL.add_key_type('rsa-sha256', algo.RsaSigner, algo.RsaVerifier)
ALL.add_key_type('secp256k1', algo.Secp256k1Signer, algo.Secp256k1Verifier)
