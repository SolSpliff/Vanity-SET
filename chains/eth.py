# Eth wallet gen
"""
Ethereum wallet generation utilities.

This module exposes a :func:`generate_wallet` function that creates a new
Ethereum account along with a BIP39 mnemonic. The private key and mnemonic
returned correspond to one another, so that the mnemonic can be used to
re‑derive the private key and address. The underlying implementation
leverages the `eth_account` library's hierarchical deterministic (HD) wallet
features. See the upstream documentation for details【420859336040195†L146-L156】.

The original implementation generated a completely random account and a
separate random mnemonic. As a result, the secret key and mnemonic were
unrelated and users could not import the wallet using the provided seed
phrase. This version corrects that behaviour by deriving the account from
the mnemonic itself.
"""

from datetime import datetime, timezone
from typing import Dict

from eth_account import Account
from mnemonic import Mnemonic


def generate_wallet(mnemonic_words: int = 24) -> Dict[str, str]:
    """Generate a new Ethereum wallet.

    Parameters
    ----------
    mnemonic_words : int, optional
        Number of words to use for the BIP39 mnemonic. Only 12 or 24 are
        accepted. Defaults to 24.

    Returns
    -------
    dict
        A dictionary containing the private key (hex string prefixed with
        ``0x``), the checksummed address, the mnemonic phrase, and the
        ISO‑8601 timestamp of creation.

    Notes
    -----
    The function uses ``eth_account.Account.create_with_mnemonic`` to
    simultaneously produce an account and its associated mnemonic. This
    ensures that the mnemonic can be used later to re‑derive the same
    account via ``Account.from_mnemonic``【420859336040195†L146-L156】.
    """
    if mnemonic_words not in (12, 24):
        raise ValueError("mnemonic_words must be 12 or 24")

    # Enable HD wallet features. This is required to use the
    # create_with_mnemonic/from_mnemonic APIs which are disabled by default
    # because they haven't been audited for production use yet. See
    # https://github.com/ethereum/eth-account#using-mnemonics for details.
    Account.enable_unaudited_hdwallet_features()

    # Generate the account and mnemonic together. The returned mnemonic is a
    # space‑separated string.
    acct, mnemonic_phrase = Account.create_with_mnemonic(num_words=mnemonic_words)

    # Extract the private key and address. ``acct.key`` is a Bytes value
    # containing the raw private key. ``hex()`` returns the key without a
    # '0x' prefix, so we explicitly add it for clarity and consistency with
    # common Ethereum tooling.
    private_key_hex = '0x' + acct.key.hex()
    address = acct.address

    return {
        "private_key_hex": private_key_hex,
        "address": address,
        "mnemonic": mnemonic_phrase,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
