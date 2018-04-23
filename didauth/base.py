from .utils import decode_string, encode_string


class SignerBase:
    def __init__(self, key_type, secret=None):
        pass

    @property
    def algorithm(self) -> str:
        return self.__class__.algorithm

    @property
    def private_key(self) -> bytes:
        pass

    @property
    def public_key(self) -> bytes:
        return self._pubkey

    def _sign(self, data: bytes) -> bytes:
        raise SystemError('Not implemented')

    def sign(self, data, return_format=None) -> bytes:
        if isinstance(data, str):
            data = data.encode('ascii')
        signed = self._sign(data)
        if not signed:
            raise SystemError('Not implemented')
        if return_format:
            signed = encode_string(signed, return_format)
        return signed


class VerifierBase:
    def __init__(self, key_type, pubkey):
        pass

    @property
    def public_key(self) -> bytes:
        pass

    def _verify(self, message: bytes, signature: bytes) -> bool:
        raise SystemError('Not implemented')

    def verify(self, message, signature, signature_format=None) -> bool:
        if signature_format:
            signature = decode_string(signature, signature_format)
        return self._verify(message, signature)


class VerifierException(Exception):
    pass


class KeyFinderBase:
    def find_key(self, key_id: str, key_type: str) -> bytes:
        raise LookupError('Key lookup not implemented')


class StaticKeyFinder(KeyFinderBase):
    def __init__(self):
        self._keys = {}

    def add_key(self, key_id, key_type, key):
        self._keys[key_id] = (key_type, key)

    def find_key(self, key_id: str, key_type: str) -> bytes:
        key = self._keys.get(key_id)
        if not key:
            return None
        if key[0] != key_type:
            return None
        return key[1]
