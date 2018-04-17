import logging
from typing import Mapping, Sequence
from urllib.parse import urlparse

import requests.auth

from .headers import HeaderSigner
from .registry import ALL as registry


LOGGER = logging.getLogger(__name__)


class SignedRequestAuth(requests.auth.AuthBase):
    """
    Sign a request using the http-signature scheme.
    https://github.com/joyent/node-http-signature/blob/master/http_signing.md

    `key_id` is the mandatory label indicating to the server which secret to
      use secret is the filename of a pem file in the case of rsa, a password
      string in the case of an hmac algorithm
    `algorithm` is one of the supported algorithms
      headers is a list of http headers to be included in the signing string,
      defaulting to "Date" alone.
    """
    def __init__(self, key_id: str, algorithm: str, secret: bytes, header_list:Sequence=None):
        self._header_list = header_list
        self._key_id = key_id
        self._signer = registry.create_signer(algorithm, secret)

    def header_signer(self, header_list: Sequence):
        return HeaderSigner(self._key_id, self._signer, header_list)

    def signed_headers(self, host: str, method: str, uri: str, headers: Mapping):
        LOGGER.info('Signing headers: %s "%s" %s', method, uri, headers)
        header_list = set() # set('(request-target)')
        header_list.update(self._header_list or headers.keys())
        hs = self.header_signer(header_list)
        result = hs.sign(headers, host=host, method=method, path=uri)
        LOGGER.info('Signed headers: %s', result)
        return result

    def __call__(self, req):
        # 'Host' header unavailable in request object at this point
        # if 'host' header is needed, extract it from the url
        host = urlparse(req.url).netloc
        headers = self.signed_headers(host, req.method, req.path_url, req.headers)
        req.headers.update(headers)
        return req
