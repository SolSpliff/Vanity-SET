# Eth wallet gen
from eth_account import Account
from mnemonic import Mnemonic
from datetime import datetime, timezone
import os

def generate_wallet(mnemonic_words=24):
    mnemo = Mnemonic("english")
    needed = 16 if mnemonic_words == 12 else 32
    entropy = os.urandom(needed)
    mnemonic_phrase = mnemo.to_mnemonic(entropy)
    acct = Account.create()
    private_key = acct.key.hex()
    address = acct.address
    return {
        "private_key_hex": private_key,
        "address": address,
        "mnemonic": mnemonic_phrase,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
