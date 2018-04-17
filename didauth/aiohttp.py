import logging
from typing import Mapping, Sequence

from aiohttp import ClientRequest

from .headers import HeaderSigner
from .registry import ALL as registry

LOGGER = logging.getLogger(__name__)


class SignedRequestAuth:
    def __init__(self, key_id: str, algorithm: str, secret: bytes, header_list:Sequence=None):
        self._header_list = header_list
        self._key_id = key_id
        self._signer = registry.create_signer(algorithm, secret)

    def header_signer(self, header_list: Sequence):
        return HeaderSigner(self._key_id, self._signer, header_list)

    def signed_headers(self, method: str, uri: str, headers: Mapping):
        LOGGER.info('Signing headers: %s "%s" %s', method, uri, headers)
        header_list = set() # set('(request-target)')
        header_list.update(self._header_list or headers.keys())
        hs = self.header_signer(header_list)
        result = hs.sign(headers, method=method, path=uri)
        LOGGER.info('Signed headers: %s', result)
        return result


class SignedRequest(ClientRequest):
    def update_auth(self, auth):
        if auth is None:
            auth = self.auth
        if isinstance(auth, SignedRequestAuth):
            signed_headers = auth.signed_headers(self.method, self.url, self.headers)
            if signed_headers:
                self.headers.clear()
                self.headers.update(signed_headers)
        else:
            return super(SignedRequest, self).update_auth(auth)
