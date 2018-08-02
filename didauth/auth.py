import logging
from typing import Mapping, Sequence

from .headers import HeaderSigner
from .registry import ALL as registry
from .utils import default_signing_headers

LOGGER = logging.getLogger(__name__)


class RequestAuthBase:
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

    def __init__(self, key_id: str, algorithm: str, secret: bytes, header_list: Sequence = None):
        self._header_list = header_list
        self._key_id = key_id
        self._sign_target = True
        self._signer = registry.create_signer(algorithm, secret)

    def header_signer(self, header_list: Sequence):
        return HeaderSigner(self._key_id, self._signer, header_list)

    @property
    def sign_target(self):
        return self._sign_target

    @sign_target.setter
    def sign_target(self, val):
        self._sign_target = True if val else False

    def signed_headers(self, method: str, path: str, headers: Mapping):
        LOGGER.debug('Signing headers: %s "%s" %s', method, path, headers)
        header_list = default_signing_headers(headers, self._header_list, self._sign_target)
        hs = self.header_signer(header_list)
        result = hs.sign(headers, method=method, path=path)
        LOGGER.debug('Signed headers: %s', result)
        return result
