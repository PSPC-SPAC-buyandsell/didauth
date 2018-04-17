import nacl.signing
import rsa
import secp256k1

from .base import SignerBase, VerifierBase


class Ed25519Signer(SignerBase):
    algorithm = 'ed25519'
    seed_length = 32

    def __init__(self, _key_type, secret=None):
        if secret:
            if len(secret) != self.seed_length:
                raise Exception('Key must be {} bytes in length'.format(self.seed_length))
            self._prvkey = nacl.signing.SigningKey(secret)
        else:
            self._prvkey = nacl.signing.SigningKey.generate()

    @property
    def private_key(self) -> bytes:
        return bytes(self._prvkey)

    @property
    def public_key(self) -> bytes:
        return bytes(self._prvkey.verify_key)

    def _sign(self, data: bytes) -> bytes:
        signed = self._prvkey.sign(data)
        return signed.signature


class Ed25519Verifier(VerifierBase):
    algorithm = 'ed25519'

    def __init__(self, _key_type, pubkey):
        if isinstance(pubkey, nacl.signing.VerifyKey):
            self._pubkey = pubkey
        else:
            self._pubkey = nacl.signing.VerifyKey(pubkey)

    def _verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._pubkey.verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False


class RsaSigner(SignerBase):
    algorithm = 'rsa-sha256'

    def __init__(self, _key_type, secret=None):
        if isinstance(secret, rsa.PrivateKey):
            self._prvkey = secret
        elif secret:
            print(secret)
            if b'RSA PRIVATE KEY' in secret:
                self._prvkey = rsa.PrivateKey.load_pkcs1(secret, format='PEM')
            else:
                raise Exception('Key format not supported')
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


class RsaVerifier(VerifierBase):
    algorithm = 'rsa-sha256'

    def __init__(self, _key_type, pubkey):
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


class Secp256k1Signer(SignerBase):
    algorithm = 'secp256k1'
    seed_length = 32

    def __init__(self, _key_type, secret=None):
        if isinstance(secret, secp256k1.PrivateKey):
            self._prvkey = secret
        elif secret:
            if len(secret) != self.seed_length:
                raise Exception('Key must be {} bytes in length'.format(self.seed_length))
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


class Secp256k1Verifier(VerifierBase):
    algorithm = 'secp256k1'

    def __init__(self, _key_type, pubkey):
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
