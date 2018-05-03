from didauth.base import SignerBase, VerifierBase
from didauth.registry import ALL as registry

ALG_RSA = 'rsa'
ALG_ED25519 = 'ed25519'
ALG_SECP = 'secp256k1'

TEST_SECRET = b'test-key-00000000000000000000000'
TEST_MESSAGE = 'my secret message'


def test_algs_present():
    algs = registry.get_supported()
    assert ALG_ED25519 in algs and registry.supports(ALG_ED25519)

    if ALG_RSA in algs:
        print('rsa support found')
    else:
        print('rsa support not found')

    if ALG_SECP in algs:
        print('secp256k1 support found')
    else:
        print('secp256k1 support not found')


def test_ed25519():
    signer = registry.create_signer(ALG_ED25519, TEST_SECRET)
    assert isinstance(signer, SignerBase)

    pubkey = signer.public_key
    assert isinstance(pubkey, bytes)

    verifier = registry.create_verifier(ALG_ED25519, pubkey)
    assert isinstance(verifier, VerifierBase)

    message = TEST_MESSAGE.encode('ascii')
    signature = signer.sign(message)
    assert isinstance(signature, bytes)

    verify = verifier.verify(message, signature)
    assert verify is True
