import libnacl
import libnacl.sign

from ..base import SignerBase, VerifierBase
from ..error import SignerException


class Signer(SignerBase):
    algorithm = 'ed25519'
    seed_length = 32

    def __init__(self, key_type, secret=None):
        super(Signer, self).__init__(key_type, secret)
        if secret:
            if len(secret) != self.seed_length:
                raise SignerException(
                    'Key must be {} bytes in length'.format(self.seed_length))
        self._signer = libnacl.sign.Signer(secret)

    @property
    def private_key(self) -> bytes:
        return bytes(self._signer.pk)

    @property
    def public_key(self) -> bytes:
        return bytes(self._signer.vk)

    def _sign(self, data: bytes) -> bytes:
        return self._signer.signature(data)


class Verifier(VerifierBase):
    algorithm = 'ed25519'

    def __init__(self, key_type, pubkey):
        super(Verifier, self).__init__(key_type)
        self._pubkey = pubkey

    def _verify(self, message: bytes, signature: bytes) -> bool:
        try:
            libnacl.crypto_sign_open(signature + message, self._pubkey)
            return True
        except ValueError:
            return False
