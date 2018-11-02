# did-auth

A Python library for signing requests using [HTTP Signatures](https://www.ietf.org/id/draft-cavage-http-signatures-09.txt) based on [Decentralized Identifiers](https://w3c-ccg.github.io/did-spec/). It supports signing and verification using RSA, Ed25519, and secp256k1.

Based on code from [httpsig](https://github.com/ahknight/httpsig) and following work on [DID Auth HTTP Proxy](https://github.com/bcgov/http-did-auth-proxy/).

### Requirements

- Python 3.5.3+
- [libnacl](https://libnacl.readthedocs.io)

### Optional integrations

- [aiohttp](https://aiohttp.readthedocs.io)
- [requests](https://pypi.org/project/requests/)
- [Python-RSA](https://github.com/sybrenstuvel/python-rsa)
- [secp256k1](https://github.com/ludbb/secp256k1-py)
