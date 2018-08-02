from typing import Sequence
from urllib.parse import urlparse

import requests.auth

from ..auth import RequestAuthBase
from ..utils import format_date_header


class SignedRequestAuth(requests.auth.AuthBase):
    def __init__(self, key_id: str, algorithm: str, secret: bytes, header_list: Sequence = None):
        self._auth = RequestAuthBase(key_id, algorithm, secret, header_list)

    @property
    def sign_target(self):
        return self._auth.sign_target

    @sign_target.setter
    def sign_target(self, val):
        self._auth.sign_target = val

    def __call__(self, req):
        if 'date' not in req.headers:
            req.headers['Date'] = format_date_header()
        if 'host' not in req.headers:
            req.headers['Host'] = urlparse(req.url).netloc
        signed_headers = self._auth.signed_headers(req.method, req.path_url, req.headers)
        req.headers.update(signed_headers)
        return req
