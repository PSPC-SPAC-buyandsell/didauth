import secp256k1

from ..base import SignerBase, VerifierBase
from ..error import SignerException


class Signer(SignerBase):
    algorithm = 'secp256k1'
    seed_length = 32

    def __init__(self, key_type, secret=None):
        super(Signer, self).__init__(key_type, secret)
        if isinstance(secret, secp256k1.PrivateKey):
            self._prvkey = secret
        elif secret:
            if len(secret) != self.seed_length:
                raise SignerException(
                    'Key must be {} bytes in length'.format(self.seed_length))
            self._prvkey = secp256k1.PrivateKey(secret, raw=True)
        else:
            self._prvkey = secp256k1.PrivateKey()

    def _sign(self, data: bytes) -> bytes:
        signed = self._prvkey.ecdsa_sign(data) #digest=hashlib.sha256
        return self._prvkey.ecdsa_serialize(signed)

    @property
    def private_key(self):
        return self._prvkey.private_key

    @property
    def public_key(self):
        return self._prvkey.pubkey.serialize()


class Verifier(VerifierBase):
    algorithm = 'secp256k1'

    def __init__(self, key_type, pubkey):
        super(Verifier, self).__init__(key_type)
        if isinstance(pubkey, secp256k1.PublicKey):
            self._pubkey = pubkey
        elif pubkey:
            self._pubkey = secp256k1.PublicKey(pubkey, True)

    @property
    def public_key(self) -> bytes:
        return self._pubkey.serialize()

    def _verify(self, message: bytes, signature: bytes) -> bool:
        signature = self._pubkey.ecdsa_deserialize(signature)
        return self._pubkey.ecdsa_verify(message, signature)
