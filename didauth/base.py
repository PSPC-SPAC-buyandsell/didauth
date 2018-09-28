from .utils import decode_string, encode_string


class KeyFinderBase:
    def __init__(self, source: 'KeyFinderBase' = None):
        self._source = source

    async def _lookup_key(self, key_id: str, key_type: str) -> bytes:
        raise LookupError('Key lookup not implemented')

    async def _cache_key(self, key_id: str, key_type: str, key: bytes):
        pass

    async def _cache_invalidate(self, key_id: str, key_type: str):
        pass

    async def find_key(self, key_id: str, key_type: str) -> bytes:
        found = await self._lookup_key(key_id, key_type)
        if not found and self._source:
            found = await self._source.find_key(key_id, key_type)
            if found:
                await self._cache_key(key_id, key_type, found)
        return found


class StaticKeyFinder(KeyFinderBase):
    def __init__(self, source: KeyFinderBase = None, caching: bool = True):
        super(StaticKeyFinder, self).__init__(source)
        self._caching = caching
        self._keys = {}

    def add_key(self, key_id: str, key_type: str, key: bytes):
        if key_type not in self._keys:
            self._keys[key_type] = {}
        self._keys[key_type][key_id] = key

    def remove_key(self, key_id: str, key_type: str):
        if key_type in self._keys and key_id in self._keys[key_type]:
            del self._keys[key_type][key_id]

    async def _cache_key(self, key_id: str, key_type: str, key: bytes):
        if self._caching:
            self.add_key(key_id, key_type, key)

    async def _cache_invalidate(self, key_id: str, key_type: str):
        self.remove_key(key_id, key_type)

    async def _lookup_key(self, key_id: str, key_type: str) -> bytes:
        if key_type in self._keys:
            return self._keys[key_type].get(key_id)
        return None


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
