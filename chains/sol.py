# Sol wallet gen
"""
Solana wallet generation utilities.

This module exposes a :func:`generate_wallet` function that creates a new
Solana keypair alongside a BIP39 mnemonic. Unlike the original
implementation (which generated a random keypair independent of the
mnemonic), this version derives the keypair deterministically from the
mnemonic itself. As a result, users can recover the same wallet from the
mnemonic using compatible derivation logic, such as the approach described
in the Solana developer cookbook【630578165640150†L52-L97】.

For a full BIP44 derivation (e.g. ``m/44'/501'/0'/0'``), consider using
the ``bip_utils`` library. This implementation uses a simplified method
where the first 32 bytes of the BIP39 seed become the secret key seed
for Ed25519. This approach is compatible with some wallets but may not
match the derivation paths used by all Solana clients. See the README for
details【630578165640150†L52-L97】. If you require strict BIP44 derivation,
install ``bip_utils`` and adapt the code accordingly.
"""

from datetime import datetime, timezone
from typing import Dict, List

import os
import base58
import hmac
import hashlib
import struct

from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from mnemonic import Mnemonic


def _slip10_ed25519_derive(seed: bytes, path: List[int]) -> bytes:
    """
    Derive an Ed25519 child seed using the SLIP‑0010/BIP32 algorithm.

    Parameters
    ----------
    seed : bytes
        The 64‑byte BIP39 seed generated from a mnemonic.
    path : list of int
        List of indices (without the hardened offset). Each index will be
        hardened by adding 0x80000000 internally.

    Returns
    -------
    bytes
        The 32‑byte secret key seed for the final path component.

    Notes
    -----
    SLIP‑0010 for Ed25519 only defines hardened derivation. This
    implementation follows the reference algorithm: each child is derived
    via ``I = HMAC‑SHA512(key=c, data=b"\x00" + k + index_be)`` where ``c``
    is the parent chain code and ``k`` is the parent secret key. The result
    ``I`` is split into a new secret key ``k`` (left 32 bytes) and new
    chain code ``c`` (right 32 bytes).
    """
    # Master key and chain code from seed
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for index in path:
        # Harden the index by adding 0x80000000
        data = b"\x00" + k + struct.pack(">L", index | 0x80000000)
        I = hmac.new(c, data, hashlib.sha512).digest()
        k, c = I[:32], I[32:]
    return k


def generate_wallet(mnemonic_words: int = 24) -> Dict[str, str]:
    """Generate a new Solana wallet using BIP44 path m/44'/501'/0'/0'.

    Parameters
    ----------
    mnemonic_words : int, optional
        Number of words for the mnemonic (12 or 24). Defaults to 24.

    Returns
    -------
    dict
        A dictionary with the private key and public key (raw hex), the
        64‑byte secret key in Base58 (compatible with Phantom), the public
        key in Base58, the mnemonic, and a timestamp.

    Notes
    -----
    The wallet is derived following the standard Solana BIP44 path
    ``m/44'/501'/0'/0'``. The final 32‑byte secret key seed is used to
    construct an Ed25519 SigningKey. Phantom and other wallets use a
    64‑byte secret key (private + public) encoded in Base58 for direct
    import; this value is provided as ``secret_key_b58``.
    """
    if mnemonic_words not in (12, 24):
        raise ValueError("mnemonic_words must be 12 or 24")

    mnemo = Mnemonic("english")
    entropy_len = 16 if mnemonic_words == 12 else 32
    entropy = os.urandom(entropy_len)
    mnemonic_phrase = mnemo.to_mnemonic(entropy)

    # BIP39 seed (64 bytes) from mnemonic with empty passphrase
    seed = mnemo.to_seed(mnemonic_phrase, passphrase="")

    # Derive the BIP44 Solana path m/44'/501'/0'/0'
    path = [44, 501, 0, 0]
    seed32 = _slip10_ed25519_derive(seed, path)

    # Construct the Ed25519 keypair
    sk = SigningKey(seed32)
    vk = sk.verify_key

    private_key_bytes = sk.encode(encoder=RawEncoder)
    public_key_bytes = vk.encode(encoder=RawEncoder)

    # Compose 64‑byte secret key (private + public) for Phantom import
    secret_key_64 = private_key_bytes + public_key_bytes

    # Base58 encodings
    secret_key_b58 = base58.b58encode(secret_key_64).decode()
    pub_b58 = base58.b58encode(public_key_bytes).decode()

    return {
        "private_key_bytes": private_key_bytes.hex(),
        "public_key_bytes": public_key_bytes.hex(),
        "secret_key_b58": secret_key_b58,
        "public_key_b58": pub_b58,
        "mnemonic": mnemonic_phrase,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
