# Sol wallet gen
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from mnemonic import Mnemonic
import base58
import os
from datetime import datetime, timezone

def generate_wallet(mnemonic_words=24):
    sk = SigningKey.generate()
    vk = sk.verify_key
    private_key = sk.encode(encoder=RawEncoder)
    public_key = vk.encode(encoder=RawEncoder)
    priv_b58 = base58.b58encode(private_key).decode()
    pub_b58 = base58.b58encode(public_key).decode()
    mnemo = Mnemonic("english")
    needed = 16 if mnemonic_words == 12 else 32
    entropy = os.urandom(needed)
    mnemonic_phrase = mnemo.to_mnemonic(entropy)
    return {
        "private_key_bytes": private_key.hex(),
        "public_key_bytes": public_key.hex(),
        "private_key_b58": priv_b58,
        "public_key_b58": pub_b58,
        "mnemonic": mnemonic_phrase,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
