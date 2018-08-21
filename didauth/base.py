from .utils import decode_string, encode_string


class SignerBase:
    def __init__(self, _key_type, _secret=None):
        self._pubkey = None

    @property
    def algorithm(self) -> str:
        return self.__class__.algorithm

    @property
    def private_key(self) -> bytes:
        pass

    @property
    def public_key(self) -> bytes:
        return self._pubkey

    def _sign(self, _data: bytes) -> bytes:
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
    def __init__(self, _key_type, _pubkey=None):
        self._pubkey = None

    @property
    def public_key(self) -> bytes:
        pass

    def _verify(self, _message: bytes, _signature: bytes) -> bool:
        raise SystemError('Not implemented')

    def verify(self, message, signature, signature_format=None) -> bool:
        if signature_format:
            signature = decode_string(signature, signature_format)
        return self._verify(message, signature)


class KeyFinderBase:
    def __init__(self, cache: 'KeyFinderBase' = None):
        self._cache = cache

    async def lookup_key(self, key_id: str, key_type: str) -> bytes:
        raise LookupError('Key lookup not implemented')

    def add_key(self, key_id: str, key_type: str, key: bytes):
        pass

    async def find_key(self, key_id: str, key_type: str, use_cache: bool = True) -> bytes:
        found = None
        if use_cache and self._cache:
            found = await self._cache.find_key(key_id, key_type)
        if not found:
            found = await self.lookup_key(key_id, key_type)
            if use_cache and self._cache:
                self._cache.add_key(key_id, key_type)
        return found


class StaticKeyFinder(KeyFinderBase):
    def __init__(self, cache: 'KeyFinderBase' = None):
        super(StaticKeyFinder, self).__init__(cache)
        self._keys = {}

    def add_key(self, key_id: str, key_type: str, key: bytes):
        self._keys[key_id] = (key_type, key)

    async def lookup_key(self, key_id: str, key_type: str) -> bytes:
        key = self._keys.get(key_id)
        if not key:
            return None
        if key[0] != key_type:
            return None
        return key[1]
