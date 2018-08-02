import libnacl.sign

from .utils import encode_string


def seed_to_did(seed):
    """
    Utility method to convert an Indy seed to a DID without creating a wallet
    Test data:
        seed: test-seed00000000000000000000000
        verkey: 2hJAJDR5N4LHDxWPADQQ1Tx19WFGDnDQXJe8HA66Td3n
        did: 47MC9bBzTfrsdETN6aSBAT
    """
    if isinstance(seed, str):
        seed = seed.encode('ascii')
    signer = libnacl.sign.Signer(seed)
    return encode_string(signer.vk[:16], 'base58')
