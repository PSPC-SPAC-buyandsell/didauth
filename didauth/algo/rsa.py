import rsa

from ..base import SignerBase, VerifierBase
from ..error import SignerException


class Signer(SignerBase):
    algorithm = 'rsa-sha256'

    def __init__(self, key_type, secret=None):
        super(Signer, self).__init__(key_type)
        if isinstance(secret, rsa.PrivateKey):
            self._prvkey = secret
        elif secret:
            if b'RSA PRIVATE KEY' in secret:
                self._prvkey = rsa.PrivateKey.load_pkcs1(secret, format='PEM')
            else:
                raise SignerException('Key format not supported')
        else:
            self._pubkey, self._prvkey = rsa.newkeys(512)

    @property
    def private_key(self) -> bytes:
        return self._prvkey and self._prvkey.save_pkcs1(format='PEM')

    @property
    def public_key(self) -> bytes:
        return self._pubkey and self._pubkey.save_pkcs1(format='PEM')

    def _sign(self, data: bytes) -> bytes:
        return rsa.sign(data, self._prvkey, 'SHA-256')


class Verifier(VerifierBase):
    algorithm = 'rsa-sha256'

    def __init__(self, key_type, pubkey):
        super(Verifier, self).__init__(key_type)
        if isinstance(pubkey, rsa.PublicKey):
            self._pubkey = pubkey
        elif pubkey:
            if b'RSA PUBLIC KEY' in pubkey:
                self._pubkey = rsa.PublicKey.load_pkcs1(pubkey)
            else:
                self._pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey)

    @property
    def public_key(self) -> bytes:
        return self._pubkey.save_pkcs1(format='PEM')

    def _verify(self, message: bytes, signature: bytes) -> bool:
        return rsa.verify(message, signature, self._pubkey)
