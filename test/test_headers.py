import asyncio
import pytest

from didauth.base import StaticKeyFinder
from didauth.headers import HeaderSigner, HeaderVerifier
from didauth.registry import ALL
from didauth.utils import decode_string, encode_string


ALG_ED25519 = 'ed25519'

TEST_DID = 'did:sov:47MC9bBzTfrsdETN6aSBAT'

TEST_SECRET = b'test-key-00000000000000000000000'


@pytest.mark.asyncio
async def test_headers():

    headers = {
        'Date': 'Thu, 01 May 2018 00:00:00 -0000',
        'Host': 'example.com',
        'User-Agent': 'Tester',
    }
    header_list = ['(request-target)']
    header_list.extend(headers.keys())
    method = 'GET'
    path = '/info/'

    signer = ALL.create_signer(ALG_ED25519, TEST_SECRET)
    hdr_signer = HeaderSigner(TEST_DID, signer, header_list)

    signed_headers = hdr_signer.sign(headers, method, path)
    assert 'authorization' in signed_headers

    lines = map('{0[0]}: {0[1]}'.format, signed_headers.items())
    print(method, path)
    print('\n'.join(lines))

    key_finder = StaticKeyFinder()
    key_finder.add_key(TEST_DID, ALG_ED25519, signer.public_key)

    verifier = HeaderVerifier(key_finder)
    verified = await verifier.verify(signed_headers, method, path)

    print('Verify result: {}'.format(verified))

    assert verified['verified'] is True
    assert verified['algorithm'] == ALG_ED25519
    assert verified['headers'] == ['(request-target)', 'date', 'host', 'user-agent']
    assert verified['keyId'] == TEST_DID
    assert verified['key'] == signer.public_key
    assert verified['signature'] == \
        '+lqX6t0Jq2nELAzFMuVDsyuz2PJmMMSF1eiXuNg7dNyD0r+t9VwGDpMlxvtrI1DdfI0yQHtsRZiO2BRz4YNXAQ=='


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(test_headers())
