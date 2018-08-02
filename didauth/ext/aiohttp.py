from aiohttp import ClientRequest

from ..auth import RequestAuthBase
from ..utils import format_date_header


class SignedRequestAuth(RequestAuthBase):
    pass


class SignedRequest(ClientRequest):
    def update_auth(self, auth):
        if auth is None:
            auth = self.auth
        if isinstance(auth, SignedRequestAuth):
            if 'date' not in self.headers:
                self.headers['Date'] = format_date_header()
            signed_headers = auth.signed_headers(self.method, self.url.path_qs, self.headers)
            if signed_headers:
                self.headers.clear()
                self.headers.update(signed_headers)
            return None
        else:
            return super(SignedRequest, self).update_auth(auth)
