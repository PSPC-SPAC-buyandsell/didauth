import base58
import libnacl.sign
from von_agent.agents import _BaseAgent

from .base import KeyFinderBase


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
    return base58.b58encode(signer.vk[:16])


class IndyKeyFinder(KeyFinderBase):
    def __init__(self, agent:_BaseAgent):
        self._agent = agent

    def find_key(key_id: str, key_type: str) -> bytes:
        if key_type != 'ed25519':
            return None
        if key_id.startswith('did:sov:'):
            key_id = key_id[8:]
        nym = self._agent.get_nym(key_id)
        if not nym:
            return None
        return base58.b58decode(nym['verkey'])
