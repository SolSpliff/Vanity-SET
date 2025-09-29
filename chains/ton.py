# chains/ton.py
from datetime import datetime, timezone
import os
from typing import List, Optional

# Prefer using tonsdk's built-in mnemonic helper if available, otherwise use python-mnemonic
try:
    from tonsdk.crypto import mnemonic_new as _tonsdk_mnemonic_new  # type: ignore
except Exception:
    _tonsdk_mnemonic_new = None

try:
    from mnemonic import Mnemonic as _Bip39Mnemonic  # type: ignore
except Exception:
    _Bip39Mnemonic = None


def _normalize_to_word_list(m) -> List[str]:
    """
    Normalize a mnemonic value `m` to a list of words.
    Accepts:
      - list/tuple of words -> returned as list
      - space-separated string -> split and returned
    """
    if isinstance(m, (list, tuple)):
        return list(m)
    if isinstance(m, str):
        return m.strip().split()
    raise ValueError("Unsupported mnemonic format; expected list or space-separated string")


def generate_wallet(mnemonic_words: int = 24, wallet_version: str = "v3r2", workchain: int = 0):
    """
    Generate a TON wallet.

    - mnemonic_words: preferred word count, defaults to 24. If 12 is requested we will try 12 first,
      and automatically fall back to 24 if the SDK rejects the 12-word phrase.
    - wallet_version: logical label like "v3r2", "v4r2", "v5r1" (resolved against WalletVersionEnum).
    - workchain: integer workchain (commonly 0).

    Returns:
      dict with keys: mnemonic (string), address_user, address_raw, public_key_hex, private_key_hex, created_at.
    """
    try:
        from tonsdk.contract.wallet import WalletVersionEnum, Wallets  # type: ignore
    except Exception as e:
        raise RuntimeError("tonsdk import failed; ensure 'tonsdk' is installed") from e

    # Helper: resolve enum members defensively
    def _resolve_enum_member(*names) -> Optional[object]:
        for nm in names:
            if hasattr(WalletVersionEnum, nm):
                return getattr(WalletVersionEnum, nm)
        return None

    # Build mapping defensively
    mapping = {
        "v3r2": _resolve_enum_member("v3r2", "v3r1"),
        "v4r2": _resolve_enum_member("v4r2", "v4r1"),
        "v5r1": _resolve_enum_member("v5r1", "hv2", "v4r2"),
    }

    ver = mapping.get(wallet_version)
    if ver is None:
        ver = _resolve_enum_member("v3r2", "hv2", "v4r2", "v3r1", "v2r2", "v2r1")
        if ver is None:
            raise RuntimeError("Could not resolve a WalletVersionEnum member from the installed tonsdk.")

    if mnemonic_words not in (12, 24):
        raise ValueError("mnemonic_words must be 12 or 24")

    # Mnemonic generation function (returns List[str])
    def _make_mnemonic(words: int) -> List[str]:
        # Try tonsdk helper first (some versions accept a length arg)
        if _tonsdk_mnemonic_new is not None:
            try:
                try:
                    m = _tonsdk_mnemonic_new(words)
                except TypeError:
                    m = _tonsdk_mnemonic_new()
                return _normalize_to_word_list(m)
            except Exception:
                # fall through to bip39 fallback below
                pass

        # Fallback to python-mnemonic package
        if _Bip39Mnemonic is None:
            raise RuntimeError(
                "No mnemonic helper available: install the 'mnemonic' package or use a tonsdk that provides mnemonic_new."
            )
        mnemo = _Bip39Mnemonic("english")
        needed = 16 if words == 12 else 32
        return _normalize_to_word_list(mnemo.to_mnemonic(os.urandom(needed)))

    # Try the requested size (12 or 24). If 12 is requested and fails, silently fall back to 24.
    mnemonic_list = _make_mnemonic(mnemonic_words)
    tried_24_fallback = False
    try:
        _mn, pub_k, priv_k, wallet = Wallets.from_mnemonics(mnemonic_list, ver, workchain)
    except Exception as e:
        ename = type(e).__name__
        if mnemonic_words == 12 and ("InvalidMnemonicsError" in ename or "invalid mnemon" in str(e).lower()):
            # silently fallback to 24-word mnemonic
            mnemonic_list = _make_mnemonic(24)
            tried_24_fallback = True
            try:
                _mn, pub_k, priv_k, wallet = Wallets.from_mnemonics(mnemonic_list, ver, workchain)
            except Exception as e2:
                # If fallback also fails, raise a clear error
                raise RuntimeError(
                    "tonsdk rejected both the requested 12-word mnemonic and the 24-word fallback. "
                    "Please check your tonsdk installation/version."
                ) from e2
        else:
            # re-raise unexpected exceptions
            raise

    # Construct outputs
    mnemonic_phrase_str = " ".join(mnemonic_list)  # present mnemonic as user-friendly string

    # tonsdk v1.0.15 uses .wc and .hash_part; provide fallback attributes for other versions
    wc_val = getattr(wallet.address, "wc", None)
    if wc_val is None:
        wc_val = getattr(wallet.address, "workchain", None)

    acct_part = getattr(wallet.address, "hash_part", None)
    if acct_part is None:
        acct_attr = getattr(wallet.address, "account_id", None)
        acct_hex = acct_attr.hex() if acct_attr is not None else None
    else:
        acct_hex = acct_part.hex()

    user_friendly = None
    try:
        # default user-friendly string
        user_friendly = wallet.address.to_string()
    except Exception:
        # If to_string fails, leave None
        user_friendly = None

    raw_addr = f"{wc_val}:{acct_hex}" if wc_val is not None and acct_hex is not None else None

    return {
        "mnemonic": mnemonic_phrase_str,
        "address_user": user_friendly,
        "address_raw": raw_addr,
        "public_key_hex": pub_k.hex() if pub_k is not None else None,
        "private_key_hex": priv_k.hex() if priv_k is not None else None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
