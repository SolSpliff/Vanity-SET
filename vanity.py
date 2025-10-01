#!/usr/bin/env python3
import pwinput
import os
import re
import sys
import json
import ast
import time
import base64
import shutil
import logging
import argparse
import threading
import getpass
from time import sleep
from collections import deque
from datetime import datetime, timezone
from contextlib import contextmanager
import atexit
from typing import List, Dict
from rich.text import Text

ACTIVE_LOCKS = set()
cfg_dir = "config"
HELP_MODE = any(arg in ("-h", "--help") for arg in sys.argv)
TOTAL_REGEX = 0

def print(x):
    if HELP_MODE:
        return
    console.print(x)
        
def cleanup_locks():
    for lockfile in list(ACTIVE_LOCKS):
        try:
            if os.path.exists(lockfile):
                os.remove(lockfile)
            ACTIVE_LOCKS.discard(lockfile)
        except Exception as e:
            logging.error(f"Failed to remove lock {lockfile}: {e}")


def reset_terminal_colors():
    try:
        sys.stdout.write("\x1b[0m")
        sys.stdout.flush()
    except Exception:
        pass


# ensure terminal reset and lock cleanup on any normal exit
atexit.register(reset_terminal_colors)
atexit.register(cleanup_locks)

# crypto / wallet libs (used in generator, keep intact)
from nacl.signing import SigningKey
from nacl.encoding import RawEncoder
from mnemonic import Mnemonic
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Rich UI
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.table import Table
from rich.align import Align

import base58

console = Console()

# ---------------------
# Settings (defaults, but may be overridden by optional settings.py)
# ---------------------
# Internal defaults
_INTERNAL_DEFAULTS = {
    "DEFAULT_CHAIN": "sol",        # sol by default
    "DEFAULT_THREADS": 2,
    "DEFAULT_AUTOSAVE": 1,
    "DEFAULT_MNEMONIC_WORDS": 24,
    "DEFAULT_MAX_HITS_PER_LABEL": None,
}


# If settings.py is missing in the current working directory, regenerate it from internal defaults.
# This ensures the app always has a settings.py to read from (CLI args still take precedence).
try:
    _cwd_settings_path = os.path.join(cfg_dir, "settings.py")
    if not os.path.exists(_cwd_settings_path):
        # write a simple settings.py containing the uppercase keys from _INTERNAL_DEFAULTS
        with open(_cwd_settings_path, "w", encoding="utf-8") as _sf:
            _sf.write("# Regenerated settings.py - values derived from internal defaults\n")
            for _k, _v in _INTERNAL_DEFAULTS.items():
                # use repr so strings are quoted correctly
                _sf.write(f"{_k} = {repr(_v)}\n")
        # do not loudly print in production; keep quiet but available in logs
except Exception:
    # best-effort regeneration; if it fails, continue without interrupting the app
    pass

# Try to import config.settings as settings.py if present
try:
    import config.settings as _user_settings  # type: ignore
    USER_SETTINGS = {k: getattr(_user_settings, k) for k in dir(_user_settings) if k.isupper()}
except Exception:
    USER_SETTINGS = {}

def _get_setting(name: str):
    # CLI will override at runtime; this helper resolves settings.py over internal defaults
    return USER_SETTINGS.get(name, _INTERNAL_DEFAULTS.get(name))


# ---------------------
# Project paths (use ./vane as the application folder)
# ---------------------
ROOT_DIR = os.getcwd()
BASE_DIR = os.path.join(ROOT_DIR, "vane")
os.makedirs(BASE_DIR, exist_ok=True)

INDEX_PATH = os.path.join(BASE_DIR, "index.json")
KDF_SALT_PATH = os.path.join(BASE_DIR, "kdf_salt")
LOG_PATH = os.path.join(BASE_DIR, "vanity.log")
HTML_DASH_PATH = os.path.join(BASE_DIR, "dashboard.html")

# Ensure logging writes to the new log path
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------------------
# Globals / default tuning
# ---------------------
MNEMONIC_WORDS = int(_get_setting("DEFAULT_MNEMONIC_WORDS") or 24)
ALL_TIME_HITS: Dict[str, int] = {}                # in-memory all-time index (label -> count)
ALL_TIME_LOCK = threading.Lock()  # protects ALL_TIME_HITS

# UI tuning
HIGHLIGHT_SECONDS = 12.0
HEADER_REFRESH_INTERVAL = 2.5    # terminal header updates every ~2.5s
HTML_REFRESH_INTERVAL = 1.0      # write HTML every 1s (independent)
LIVE_REFRESH_PER_SEC = 1         # Live's base refresh; we'll call live.refresh() when needed
RECENT_SHOW_MAX = 40
RATE_SMOOTH_SECONDS = 10         # smooth average window for rate/sparkline

# Fade colors (hex)
COLOR_NEW = "#7ef58a"   # bright green
COLOR_OLD = "#8b8b8b"   # dim gray

# ---------------------
# Utility / atomic write / file lock
# ---------------------
def ensure_app_dir():
    os.makedirs(BASE_DIR, exist_ok=True)

def atomic_write_bytes(path: str, data: bytes):
    tmp = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, path)

@contextmanager
def file_lock(lockname: str, timeout: float = 10.0):
    """
    Cross-platform file-based lock context manager. Lock files are placed in BASE_DIR for the app.
    """
    ensure_app_dir()
    lockpath = os.path.join(BASE_DIR, f"{lockname}.lock")
    start = time.time()
    f = None
    try:
        try:
            f = open(lockpath, "a+b")
        except Exception:
            f = open(lockpath, "a+")
        ACTIVE_LOCKS.add(lockpath)

        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if (time.time() - start) > timeout:
                        raise TimeoutError("Timeout acquiring lock")
                    time.sleep(0.05)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if (time.time() - start) > timeout:
                        raise TimeoutError("Timeout acquiring lock")
                    time.sleep(0.05)

        try:
            f.seek(0)
            f.truncate()
            pid_bytes = str(os.getpid()).encode("utf-8")
            f.write(pid_bytes)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        except Exception:
            pass

        yield
    finally:
        try:
            if f is not None:
                if os.name == "nt":
                    try:
                        import msvcrt
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    try:
                        import fcntl
                        fcntl.flock(f, fcntl.LOCK_UN)
                    except Exception:
                        pass
        finally:
            try:
                if f is not None:
                    f.close()
            except Exception:
                pass
            try:
                if os.path.exists(lockpath):
                    os.remove(lockpath)
            except Exception:
                pass
            ACTIVE_LOCKS.discard(lockpath)


# ---------------------
# Regex loader (robust)
# ---------------------
def _strip_comments(text: str) -> str:
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        if "//" in ln:
            ln = ln.split("//", 1)[0]
        out.append(ln)
    return "\n".join(out)

def _try_autocorrect_json(text: str):
    t = _strip_comments(text)
    t = re.sub(r",\s*(\}|])", r"\1", t)
    def replace_single_quotes(s: str) -> str:
        return re.sub(r"(?P<prefix>[:\{\s,])'(?P<inner>[^']*?)'(?P<suffix>[\s,\}\]])", r'\g<prefix>"\g<inner>"\g<suffix>', s)
    t2 = replace_single_quotes("\n" + t + "\n")
    t2 = t2[1:-1] if t2.startswith("\n") and t2.endswith("\n") else t2
    if t2.strip().startswith("{") and ":" in t2:
        return True, t2
    return False, text

def load_patterns_from_json(path="regex.shared.json"):
    global TOTAL_REGEX
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            txt = fh.read()
    except Exception as e:
        print(f"[red]✗ Failed to read {path}: {e}[/red]")
        logging.exception("Failed to read regexes.json")
        return {}

    try:
        obj = json.loads(txt)
        if isinstance(obj, dict):
            TOTAL_REGEX += len(obj)
            print(f"[green]✓ Loaded {len(obj)} shared pattern(s) from {path} (valid JSON).[/green]")
            return {str(k): str(v) for k, v in obj.items()}
    except json.JSONDecodeError as jde:
        print(f"[yellow]Warning:[/yellow] Failed to parse {path} as JSON at line {jde.lineno} column {jde.colno}. Attempting fallbacks...")
        logging.warning("JSON decode error in regexes.json: %s", jde)

    try:
        obj = ast.literal_eval(txt)
        if isinstance(obj, dict):
            print(f"[green]✓ Loaded {len(obj)} shared pattern(s) from {path} [/green]")
            return {str(k): str(v) for k, v in obj.items()}
    except Exception:
        pass

    did_fix, corrected = _try_autocorrect_json(txt)
    if did_fix:
        try:
            obj = json.loads(corrected)
            if isinstance(obj, dict):
                bak = path + ".bak"
                try:
                    shutil.copy2(path, bak)
                    print(f"[yellow]Backup created:[/yellow] {bak}")
                except Exception:
                    print(f"[yellow]Warning:[/yellow] Could not create backup {bak}")
                try:
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump(obj, fh, indent=2)
                    print(f"[green]✓ Auto-corrected and wrote valid JSON to {path}[/green]")
                except Exception:
                    print(f"[yellow]Warning:[/yellow] Auto-correct succeeded but failed to write corrected file.")
                return {str(k): str(v) for k, v in obj.items()}
        except Exception:
            pass

    lines = [ln.strip() for ln in txt.splitlines() if ln.strip() and not ln.strip().startswith("#") and not ln.strip().startswith("//")]
    parsed = {}
    for ln in lines:
        if "," in ln:
            p, lbl = ln.split(",", 1)
            p = p.strip()
            lbl = lbl.strip() or "default"
            if p:
                parsed[p] = lbl
        else:
            parsed[ln] = "default"
    if parsed:
        TOTAL_REGEX += len(parsed)
        print(f"[green]✓ Loaded {len(parsed)} shared pattern(s) from {path} using line-based fallback.[/green]")
        return {str(k): str(v) for k, v in parsed.items()}

    print(f"[red]✗ Could not parse shared pattern(s) from {path}. No patterns loaded.[/red]")
    print("Expected formats (examples):")
    print('- JSON:  {"^abc": "label_a", "xyz$": "label_b"}')
    print("- Python dict (single quotes ok): {'^abc': 'label_a'}")
    print("- Plain lines: ^abc,label_a (or just '^abc' -> default)")

    return {}

# load patterns at import


# pattern loading: prefer config/regex.shared.json and per-chain files (regex.<chain>.json)
SHARED_PATTERNS = {}

for sp in (os.path.join("config","regex.shared.json"), os.path.join("config","regexes.json"), "regexes.json"):
    try:
        if os.path.exists(sp):
            sp_loaded = load_patterns_from_json(sp)
            if sp_loaded:
                SHARED_PATTERNS = sp_loaded
                TOTAL_REGEX += len(SHARED_PATTERNS)
                print(f"[green]✓ Loaded {len(SHARED_PATTERNS)} shared pattern(s) from {sp}[/green]")
                break
    except Exception as e:
        logging.exception(f"Failed loading shared shared pattern(s) from {sp}: {e}")
if not SHARED_PATTERNS:
    print("[yellow]Notice:[/yellow] No shared patterns found in config/regex.shared.json or regexes.json.")

# Per-chain patterns are read from config/regex.<chain>.json files (e.g. regex.sol.json)
CHAIN_PATTERNS = {}
known_chains = ( "sol", "eth", "ton" )
for ck in known_chains:
    pth = os.path.join("config", f"regex.{ck}.json")
    try:
        if os.path.exists(pth):
            loaded = load_patterns_from_json(pth)
            if loaded:
                CHAIN_PATTERNS[ck] = loaded
                print(f"[green]✓ Loaded {len(loaded)} pattern(s) for chain '{ck}' from {pth}[/green]")
    except Exception as e:
        logging.exception(f"Failed to load chain-specific patterns for {ck} from {pth}: {e}")

# Migrate legacy config/regex.chain.json entries (if present) into individual files and merge
legacy_chain_path = os.path.join("config", "regex.chain.json")
if os.path.exists(legacy_chain_path):
    try:
        with open(legacy_chain_path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
            if isinstance(obj, dict):
                for ck, mapping in obj.items():
                    if isinstance(mapping, dict) and mapping:
                        # merge mappings into CHAIN_PATTERNS[ck]
                        mapping_clean = {str(k): str(v) for k, v in mapping.items()}
                        if ck in CHAIN_PATTERNS:
                            CHAIN_PATTERNS[ck].update(mapping_clean)
                        else:
                            CHAIN_PATTERNS[ck] = mapping_clean
                        # write out to per-chain file for convenience
                        outp = os.path.join("config", f"regex.{ck}.json")
                        try:
                            with open(outp, "w", encoding="utf-8") as wf:
                                json.dump(CHAIN_PATTERNS[ck], wf, indent=2)
                        except Exception:
                            logging.exception(f"Failed to write migrated chain file {outp}")
        print(f"[green]✓ Migrated legacy chain shared pattern(s) from {legacy_chain_path} into per-chain files (if any).[/green]")
    except Exception as e:
        logging.exception(f"Failed reading legacy chain patterns: {e}")

# Ensure per-chain template files exist (empty objects) if nothing provided
for ck in known_chains:
    pth = os.path.join(cfg_dir, f"regex.{ck}.json")
    if not os.path.exists(pth):
        try:
            with open(pth, "w", encoding="utf-8") as wf:
                json.dump({}, wf, indent=2)
        except Exception:
            logging.exception(f"Failed to create template per-chain regex file: {pth}")

# Back-compat: PATTERNS default to shared patterns
PATTERNS = dict(SHARED_PATTERNS)
compiled_patterns = {re.compile(p, re.IGNORECASE): name for p, name in PATTERNS.items()}

# container for per-chain compiled patterns (populated when chains are initialized)
CHAIN_COMPILED = {}


# ---------------------
# KDF and Fernet
# ---------------------
def derive_key_from_password(password: str) -> bytes:
    ensure_app_dir()
    if not os.path.exists(KDF_SALT_PATH):
        salt = os.urandom(16)
        try:
            with open(KDF_SALT_PATH, "wb") as sf:
                sf.write(salt)
                sf.flush()
                try:
                    os.fsync(sf.fileno())
                except Exception:
                    pass
        except Exception:
            logging.exception("Failed writing kdf salt")
    else:
        try:
            with open(KDF_SALT_PATH, "rb") as sf:
                salt = sf.read()
        except Exception:
            salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key

def get_fernet(password: str) -> Fernet:
    return Fernet(derive_key_from_password(password))

def encrypt_data(obj, password: str) -> bytes:
    return get_fernet(password).encrypt(json.dumps(obj).encode("utf-8"))

def decrypt_data(token: bytes, password: str):
    return json.loads(get_fernet(password).decrypt(token).decode("utf-8"))

# ---------------------
# Wallet generator fallback (original in-project ed25519 fallback)
# ---------------------
def generate_wallet_internal():
    sk = SigningKey.generate()
    vk = sk.verify_key
    private_key = sk.encode(encoder=RawEncoder)
    public_key = vk.encode(encoder=RawEncoder)
    priv_b58 = base58.b58encode(private_key).decode()
    pub_b58 = base58.b58encode(public_key).decode()
    mnemo = Mnemonic("english")
    needed = 16 if MNEMONIC_WORDS == 12 else 32
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

# ---------------------
# Index helpers
# ---------------------
def load_index():
    if not os.path.exists(INDEX_PATH):
        return {}
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        logging.exception("Failed to read index")
        return {}

def write_index_atomic(index: dict):
    ensure_app_dir()
    atomic_write_bytes(INDEX_PATH, json.dumps(index, indent=2).encode("utf-8"))

# ---------------------
# Save helpers (now writes under BASE_DIR/<chain>/<label>.key.encrypted)
# ---------------------
def save_hit(data: dict, label: str, password: str, chain: str, dry_run=False, max_hits_per_label=None):
    """
    Save one encrypted hit for a given chain and label.
    Files are written to: BASE_DIR/<chain>/<label>.key.encrypted
    This function preserves the previous encryption behavior; only the path changed.
    """
    ensure_app_dir()
    chain_dir = os.path.join(BASE_DIR, chain)
    os.makedirs(chain_dir, exist_ok=True)
    filepath = os.path.join(chain_dir, f"{label}.key.encrypted")
    with file_lock(f"{chain}_{label}"):
        existing = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "rb") as f:
                    token = f.read()
                existing = decrypt_data(token, password)
                if not isinstance(existing, list):
                    existing = []
            except InvalidToken:
                print(f"[red]✗ Invalid password when reading {filepath}[/red]")
                logging.warning("Invalid password reading %s", filepath)
                return
            except Exception:
                logging.exception("Error reading existing file")
                existing = []

        # enforce max hits per label (all-time)
        if max_hits_per_label is not None and int(max_hits_per_label) > 0:
            current_alltime = None
            with ALL_TIME_LOCK:
                current_alltime = ALL_TIME_HITS.get(label, 0)
            if current_alltime >= max_hits_per_label:
                logging.info("Skipping save for %s: reached max %d", label, max_hits_per_label)
                return

        existing.append(data)

        if not dry_run:
            try:
                token = encrypt_data(existing, password)
                atomic_write_bytes(filepath, token)
            except Exception:
                logging.exception("Failed to write encrypted label file")
                print(f"[red]✗ Failed to write {filepath}[/red]")
                return

            # update on-disk index atomically
            idx = load_index()
            idx[label] = len(existing)
            try:
                write_index_atomic(idx)
            except Exception:
                logging.exception("Failed updating index.json")

            # update in-memory ALL_TIME_HITS so dashboard sees it immediately
            with ALL_TIME_LOCK:
                ALL_TIME_HITS[label] = len(existing)
        else:
            logging.info("[dry-run] would save %s (now has %d entries)", filepath, len(existing))

# ---------------------
# Decrypt helpers
# ---------------------
def decrypt_file(filepath: str, password: str):
    try:
        with open(filepath, "rb") as f:
            token = f.read()
    except Exception as e:
        print(f"[red]✗ Unable to read {filepath}: {e}[/red]")
        logging.exception("Failed to read for decrypt %s", filepath)
        return
    try:
        data = decrypt_data(token, password)
    except InvalidToken:
        print(f"[red]✗ Invalid password or corrupted file: {filepath}[/red]")
        logging.warning("Invalid token for %s", filepath)
        return
    except Exception:
        logging.exception("Decryption failed for %s", filepath)
        print(f"[red]✗ Decryption error for {filepath}[/red]")
        return
    outpath = filepath.rsplit(".key.encrypted", 1)[0] + ".json"
    try:
        atomic_write_bytes(outpath, json.dumps(data, indent=2).encode("utf-8"))
        print(f"[green]✓ Decrypted:[/green] {outpath}")
    except Exception:
        logging.exception("Failed write decrypted %s", outpath)
        print(f"[red]✗ Failed to write decrypted file: {outpath}[/red]")

def decrypt_all(password: str, folder=BASE_DIR):
    if not os.path.isdir(folder):
        print(f"[yellow]No matches folder found: {folder}[/yellow]")
        return
    for root, dirs, files in os.walk(folder):
        for fname in files:
            if fname.endswith(".key.encrypted"):
                decrypt_file(os.path.join(root, fname), password)

# ---------------------
# Worker (chain-aware): calls chain_module.generate_wallet if available
# ---------------------
def worker(matches_per_save, password, stop_flag, processed_counter, hits_per_label, lock, found_wallets, dry_run, max_hits_per_label, verbose, chain_key, chain_mod):
    """
    chain_key: e.g. 'sol', 'eth', 'ton'
    chain_mod: module object (imported chains.<chain>) or None -> fallback to internal generator
    """
    local_hits = []
    local_count = 0
    while not stop_flag["stop"]:
        try:
            if chain_mod is not None:
                # call module's generate_wallet API — pass mnemonic_words for compatibility
                try:
                    w = chain_mod.generate_wallet(mnemonic_words=MNEMONIC_WORDS)
                except TypeError:
                    # fallback to no-arg call if signature differs
                    w = chain_mod.generate_wallet()
            else:
                w = generate_wallet_internal()
            # choose address key depending on chain output
            address = w.get("public_key_b58") or w.get("address") or w.get("address_user") or w.get("public_key_hex") or ""
            if verbose:
                logging.debug(f"[{chain_key}] Generated: {address}")

            with lock:
                processed_counter["count"] += 1

            # pattern matching using compiled_patterns (pattern -> label)
            patterns_to_use = CHAIN_COMPILED.get(chain_key, compiled_patterns)
            for regex, label in patterns_to_use.items():
                try:
                    if regex.search(address):
                        with lock:
                            hits_per_label[f"{chain_key}:{label}"] = hits_per_label.get(f"{chain_key}:{label}", 0) + 1
                            found_wallets.append((chain_key, label, address, time.time(), w))
                        local_hits.append((w, label))
                        local_count += 1

                        if local_count >= matches_per_save:
                            with lock:
                                for wl, lbl in local_hits:
                                    save_hit(wl, lbl, password, chain=chain_key, dry_run=dry_run, max_hits_per_label=max_hits_per_label)
                            local_hits = []
                            local_count = 0
                        break
                except Exception:
                    logging.exception("Pattern match exception")
        except Exception:
            logging.exception("Worker exception")
            time.sleep(0.05)
    # on exit, flush any remaining local hits
    if local_hits:
        try:
            with lock:
                for w, lbl in local_hits:
                    save_hit(w, lbl, password, chain=chain_key, dry_run=dry_run, max_hits_per_label=max_hits_per_label)
        except Exception:
            logging.exception("Failed to flush local hits on worker exit")

# ---------------------
# Keypress wait
# ---------------------
def wait_for_keypress(prompt="Press any key to continue..."):
    print(prompt)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.getch()
        else:
            import sys, tty, termios
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        input("(press Enter)")

# ---------------------
# Show index
# ---------------------
def show_index_and_exit():
    idx = load_index()
    if not idx:
        print("[yellow]Index is empty or missing.[/yellow]")
        return
    table = Table(title="All-time hits (index.json)")
    table.add_column("Label")
    table.add_column("Count", justify="right")
    for k, v in sorted(idx.items(), key=lambda kv: kv[0]):
        table.add_row(k, str(v))
    print(table)

# ---------------------
# Helpers for UI, color interpolation, sparkline, HTML
# ---------------------
def time_ago_seconds(ts: float, now: float):
    if ts is None:
        return "—"
    delta = int(max(0, now - ts))
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta//60}m"
    if delta < 86400:
        return f"{delta//3600}h"
    return f"{delta//86400}d"

def lerp(a: int, b: int, t: float) -> int:
    return int(a + (b - a) * t)

def interpolate_hex_color(hex_a: str, hex_b: str, t: float) -> str:
    """Interpolate between two hex colors like '#rrggbb'."""
    ha = hex_a.lstrip('#')
    hb = hex_b.lstrip('#')
    ra, ga, ba = int(ha[0:2], 16), int(ha[2:4], 16), int(ha[4:6], 16)
    rb, gb, bb = int(hb[0:2], 16), int(hb[2:4], 16), int(hb[4:6], 16)
    r = lerp(ra, rb, t)
    g = lerp(ga, gb, t)
    b = lerp(ba, bb, t)
    return "#{:02x}{:02x}{:02x}".format(r, g, b)

BLOCKS = "▁▂▃▄▅▆▇█"
def sparkline_from_list(values, width=30):
    if not values:
        return " " * width
    vals = list(values)[-width:]
    maxv = max(vals) if max(vals) > 0 else 1
    out = []
    for v in vals:
        idx = int((v / maxv) * (len(BLOCKS) - 1))
        out.append(BLOCKS[max(0, min(len(BLOCKS)-1, idx))])
    return "".join(out).rjust(width)

def ease_out(t: float) -> float:
    """Ease-out curve: t in [0,1] -> eased t. Using quadratic ease-out: 1 - (1-t)^2"""
    t = max(0.0, min(1.0, t))
    return 1.0 - (1.0 - t) * (1.0 - t)

def build_html_snapshot(header, table_rows, recent_rows, sparkline_text, updated_iso):
    """table_rows: list of (label, session, alltime, lastseen)
       recent_rows: list of (label, addr, color_hex, age_str) newest-first
    """
    rows_html = "\n".join(
        f"<tr><td>{label}</td><td style='text-align:right'>{session}</td><td style='text-align:right'>{alltime}</td><td style='text-align:right;color:gray'>{lastseen}</td></tr>"
        for label, session, alltime, lastseen in table_rows
    )
    # Each recent entry is clickable to copy address. newest-first order preserved.
    recent_html = "\n".join(
        f"<div style='padding:6px; font-family:monospace; color:{color};'>"
        f"<button onclick=\"copyText('{addr}')\" class='copy-btn' title='Copy address' aria-label='Copy address'>★ {label}</button> "
        f"<span class='addr' style='color:inherit'>{addr}</span>"
        f"<div style='color:gray;font-size:smaller;margin-bottom:8px'>{age}</div>"
        f"</div>"
        for label, addr, color, age in recent_rows
    )
    # HTML includes auto-reload JavaScript (more subtle than meta-refresh) and a theme toggle
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Vanity Dashboard</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    :root {{
      --bg-dark: #0b1220;
      --panel-dark: #0f172a;
      --text-light: #e6eef8;
      --muted: #98a0b4;
    }}
    body[data-theme='dark'] {{
      background: var(--bg-dark);
      color: var(--text-light);
    }}
    body[data-theme='light'] {{
      background: #f9fafb;
      color: #0b1220;
    }}
    .header{{padding:10px;border-radius:8px;margin-bottom:10px; background: var(--panel-dark); color:var(--text-light)}}
    .controls{{float:right}}
    .spark{{font-family:monospace;letter-spacing:1px;font-size:16px}}
    .copy-btn{{background:none;border:none;padding:0;margin:0;cursor:pointer;font-weight:700;color:inherit}}
    .addr{{font-family:monospace;word-break:break-all}}
    .recent {{margin-top:12px}}
    table {{width:100%;border-collapse:collapse;margin-bottom:8px}}
    th,td {{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,0.04)}}
    body[data-theme='light'] th, body[data-theme='light'] td {{border-bottom:1px solid #eee}}
    .small {{color:var(--muted);font-size:0.9em}}
    .theme-toggle {{cursor:pointer;padding:4px 8px;border-radius:6px;border:1px solid rgba(255,255,255,0.06);background:transparent;color:inherit}}
  </style>
  <script>
    // Auto-reload small differences: if page visible, poll for changes every 1s and reload if timestamp changed
    let lastUpdated = "{updated_iso}";
    async function pollReload() {{
      try {{
        let r = await fetch(location.href, {{cache: "no-store"}});
        if (!r.ok) return;
        let txt = await r.text();
        // crude parse: look for 'Updated: ' line; fallback to full reload every 10s
        let m = txt.match(/Updated:\\s*([^<\\n\\r]+)/);
        if (m && m[1] && m[1] !== lastUpdated) {{
          lastUpdated = m[1];
          location.reload();
        }}
      }} catch(e) {{ /* ignore */ }}
    }}
    // Toggle theme
    function toggleTheme() {{
      const cur = document.body.getAttribute('data-theme') || 'dark';
      const nxt = cur === 'dark' ? 'light' : 'dark';
      document.body.setAttribute('data-theme', nxt);
      localStorage.setItem('vanity_theme', nxt);
    }}
    function copyText(txt) {{
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(txt).then(()=>{{/* ok */}}, ()=>{{ fallbackCopy(txt); }});
      }} else {{ fallbackCopy(txt); }}
    }}
    function fallbackCopy(txt) {{
      const ta = document.createElement('textarea');
      ta.value = txt;
      document.body.appendChild(ta);
      ta.select();
      try {{ document.execCommand('copy'); }} catch(e){{ }}
      ta.remove();
      alert('Copied to clipboard:\\n' + txt);
    }}
    window.addEventListener('load', ()=> {{
      const saved = localStorage.getItem('vanity_theme') || 'dark';
      document.body.setAttribute('data-theme', saved);
      // poll only when visible
      setInterval(()=> {{ if (!document.hidden) pollReload(); }}, 1000);
    }});
  </script>
</head>
<body>
  <div class="header">
    <div style="display:flex;align-items:center;justify-content:space-between">
      <div>
        <strong style="font-size:1.05em">{header}</strong>
        <div class="small" style="margin-top:6px">{sparkline_text} &nbsp; <span style="margin-left:8px">Updated: {updated_iso}</span></div>
      </div>
      <div class="controls">
        <button class="theme-toggle" onclick="toggleTheme()">☀️/🌙</button>
      </div>
    </div>
  </div>

  <h3>Tally</h3>
  <table>
    <thead><tr><th>Label</th><th style="text-align:right">Session</th><th style="text-align:right">All-time</th><th style="text-align:right">Last seen</th></tr></thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <div class="recent">
    <h3>Recent matches (click label/star to copy address)</h3>
    {recent_html}
  </div>
</body>
</html>"""
    return html.encode("utf-8")

# ---------------------
# HTML writer helper (periodic, independent)
# ---------------------
def maybe_write_html_snapshot_atomic(lock, recent_lines, hits_now_local, label_last_seen_local,
                                     rate_window_local, processed_counter_local, patterns_count, threads_count,
                                     autosave_flag, mnemonic_words, html_path, last_html_write_ref, html_interval=1.0):
    """
    Best-effort HTML writer that snapshots relevant state under lock and writes atomically.
    Returns new last_html_write timestamp (or unchanged on failure).
    """
    now = time.time()
    if (now - last_html_write_ref) < html_interval:
        return last_html_write_ref

    # copy state quickly under lock
    with lock:
        recent_copy = list(recent_lines[-RECENT_SHOW_MAX:])
        hits_copy = dict(hits_now_local)
        last_seen_copy = dict(label_last_seen_local)
        processed = processed_counter_local["count"]
        rate_copy = list(rate_window_local)

    try:
        # smooth rate: per-second average across last RATE_SMOOTH_SECONDS (or available)
        if rate_copy:
            window = rate_copy[-RATE_SMOOTH_SECONDS:]
            avg_rate = sum(window) / len(window)
        else:
            avg_rate = 0
        spark = sparkline_from_list(rate_copy, width=30)

        keys = sorted(set(list(hits_copy.keys()) + list(last_seen_copy.keys())),
                      key=lambda k: (-hits_copy.get(k, 0), -ALL_TIME_HITS.get(k, 0), k))
        table_rows = []
        for k in keys:
            s = hits_copy.get(k, 0)
            a = ALL_TIME_HITS.get(k, 0)
            last_ts = last_seen_copy.get(k)
            last_seen_str = time_ago_seconds(last_ts, time.time()) if last_ts is not None else "—"
            table_rows.append((k, s, a, last_seen_str))

        recent_rows = []
        for lbl, addr, ts in reversed(recent_copy):
            age = time.time() - ts
            t = min(max(age / HIGHLIGHT_SECONDS, 0.0), 1.0)
            t_eased = ease_out(t)
            color = interpolate_hex_color(COLOR_NEW, COLOR_OLD, t_eased)
            recent_rows.append((lbl, addr, color, time_ago_seconds(ts, time.time())))

        header_plain = f"Patterns: {patterns_count} | Threads: {threads_count} | Autosave: {autosave_flag} | Processed: {processed}"
        html = build_html_snapshot(header_plain, table_rows, recent_rows, spark, datetime.now(timezone.utc).isoformat())
        atomic_write_bytes(html_path, html)
        return time.time()
    except Exception:
        logging.exception("Failed writing periodic HTML snapshot")
        return last_html_write_ref

# ---------------------
# Main
# ---------------------
def main():
    global MNEMONIC_WORDS, ALL_TIME_HITS

    parser = argparse.ArgumentParser(
        description="Vanity address generator. Uses regexes.json patterns to search addresses; saves encrypted matches.",
        epilog="Defaults may be configured in settings.py in the project root. CLI args override settings.py."
    )
    parser.add_argument("--autosave", type=int, default=int(_get_setting("DEFAULT_AUTOSAVE") or 1),
                        help="Autosave matches to encrypted files (1=yes, 0=no). Default from config.settings.py or 1.")
    parser.add_argument("--threads", type=int, default=int(_get_setting("DEFAULT_THREADS") or 1),
                        help="Number of worker threads per chain (default from config.settings.py).")
    parser.add_argument("--decrypt", nargs="?", const=True,
                        help="Decrypt .key.encrypted files. If provided without argument, decrypts all.")
    parser.add_argument("--mnemonic-words", type=int, choices=(12, 24), default=int(_get_setting("DEFAULT_MNEMONIC_WORDS") or 24),
                        help="Mnemonic length to generate (12 or 24). Default from config.settings.py.")
    parser.add_argument("--dry-run", action="store_true", help="Do not write encrypted files; only simulate.")
    parser.add_argument("--show-index", action="store_true", help="Show the all-time index and exit.")
    parser.add_argument("--max-hits-per-label", type=int, default=_get_setting("DEFAULT_MAX_HITS_PER_LABEL"),
                        help="Max hits to keep per label (all-time). Default from config.settings.py or unlimited. Use 0 or negative for unlimited.")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--chain", choices=("sol", "eth", "ton", "all"), default=_get_setting("DEFAULT_CHAIN") or "sol",
                        help="Which chain to generate for (sol default). Use 'all' to run all available chains in parallel.")
    parser.add_argument("--allchains", action="store_true", help="Alias for --chain all")
    args = parser.parse_args()

    # resolve aliases
    if args.allchains:
        args.chain = "all"

    MNEMONIC_WORDS = args.mnemonic_words

    # Clear screen
    os.system("cls" if os.name == "nt" else "clear")

    if args.show_index:
        show_index_and_exit()
        return

    if args.decrypt:
        password = pwinput.pwinput("Enter password for decryption: ", mask="*")
        if args.decrypt is True:
            decrypt_all(password)
        else:
            decrypt_file(args.decrypt, password)
        return

    # prompt for password (confirm)
    password = pwinput.pwinput("Enter password for .key.encrypted files: ", mask="*")
    password_confirm = pwinput.pwinput("Confirm password: ", mask="*")
    if password != password_confirm:
        print("[red]Passwords do not match. Exiting.[/red]")
        return

    # Load index into memory for immediate tally updates
    ALL_TIME_HITS = load_index()
    if ALL_TIME_HITS is None:
        ALL_TIME_HITS = {}

    # determine active chains
    chain_map = {
        "sol": "chains.sol",
        "eth": "chains.eth",
        "ton": "chains.ton"
    }
    active_chain_keys = []
    active_chain_modules = {}

    if args.chain == "all":
        selected = ["sol", "eth", "ton"]
    else:
        selected = [args.chain]

    for key in selected:
        modname = chain_map.get(key)
        try:
            mod = __import__(modname, fromlist=["*"])
            active_chain_modules[key] = mod
            active_chain_keys.append(key)
            print(f"[green]Loaded chain module:[/green] {modname}")
        except Exception as e:
            print(f"[yellow]Warning:[/yellow] Could not import {modname}: {e}. Falling back to internal generator for this chain.")
            active_chain_modules[key] = None
            active_chain_keys.append(key)

    # show loaded patterns and mnemonic length

    # Build merged patterns: include shared + selected chain(s), avoid duplicates (chain wins)
    selected_chains = []
    try:
        if 'active_chain_keys' in globals() and active_chain_keys:
            selected_chains = list(active_chain_keys)
    except Exception:
        selected_chains = []
    if not selected_chains:
        if getattr(args, "allchains", False) or getattr(args, "chain", None) == "all":
            selected_chains = list(CHAIN_PATTERNS.keys())
        else:
            if getattr(args, "chain", None):
                selected_chains = [args.chain]
    if not selected_chains:
        default_chain = (_get_setting("DEFAULT_CHAIN") or "sol")
        if default_chain in CHAIN_PATTERNS:
            selected_chains = [default_chain]

    # Start merging
    shared_only = dict(SHARED_PATTERNS)
    chain_only = {}
    conflicts = []

    for ck in selected_chains:
        cp = CHAIN_PATTERNS.get(ck, {}) or {}
        for p, lbl in cp.items():
            if p in shared_only:
                if shared_only[p] != lbl:
                    conflicts.append((p, shared_only[p], lbl, ck))
                chain_only[p] = lbl
                del shared_only[p]
            else:
                chain_only[p] = lbl

    combined = dict(shared_only)
    combined.update(chain_only)

    # Ensure global PATTERNS and compiled_patterns reflect the merged set
    try:
        PATTERNS.clear()
        PATTERNS.update(combined)
        compiled_patterns.clear()
        compiled_patterns.update({re.compile(p, re.IGNORECASE): name for p, name in PATTERNS.items()})
    except Exception:
        # If PATTERNS/compiled_patterns not yet defined, avoid crashing
        pass



    print(f"\n[bold green]Loaded {len(combined)} pattern(s) (shared + selected chain(s): {', '.join(selected_chains)})[/bold green]")
    if conflicts:
        print(f"[yellow]Warning: {len(conflicts)} overlapping pattern(s) found; chain-specific labels will be used.[/yellow]")
        for p, s_lbl, c_lbl, ck in conflicts:
            console.print("  ", Text("Overlap:", style="yellow"),
                      " Pattern ", Text(p, style="magenta"),
                      " - shared label:", Text(s_lbl, style="cyan"),
                      " -> chain(", str(ck), ") label:", Text(c_lbl, style="cyan"))
            #print(f"  [yellow]Overlap:[/] Pattern [magenta]{p}[/magenta] - shared label:[cyan]{s_lbl}[/cyan] -> chain({ck}) label:[cyan]{c_lbl}[/cyan]")

    if shared_only:
        print("\n[bold]Shared patterns:[/bold]")
        for p, lbl in shared_only.items():
            console.print(" • ", Text(p, style="magenta"), "  →  ", Text(lbl, style="cyan"))
            #print(f" • [magenta]{p}[/magenta]  →  [cyan]{lbl}[/cyan]")

    if chain_only:
        print(f"\n[bold]Chain-specific patterns ({', '.join(selected_chains)}):[/bold]")
        for p, lbl in chain_only.items():
            console.print(" • ", Text(p, style="yellow"), "  →  ", Text(lbl, style="cyan"))
            #print(f" • [yellow]{p}[/yellow]  →  [cyan]{lbl}[/cyan]")

    print(f"\n[bold green]Mnemonic length chosen:[/bold green] {MNEMONIC_WORDS} words\n")
    if args.dry_run:
        print("[yellow]Dry-run mode: files will NOT be written.[/yellow]\n")
    wait_for_keypress("Press any key to continue (this will clear the screen)...")

    # clear and run
    os.system("cls" if os.name == "nt" else "clear")

    stop_flag = {"stop": False}
    processed_counter = {"count": 0}
    # Per-session per-label hits: label -> count
    hits_per_label = {}
    found_wallets = []                # shared list of (chain_key, label, addr, ts, wallet)
    lock = threading.Lock()

    # prepare worker threads per selected chain
    threads = []
    try:
        for ck, mod in active_chain_modules.items():
            # build per-chain compiled patterns (shared + chain-specific)
            # avoid duplicating patterns: keep shared patterns separate and only add chain-specific patterns
            chain_specific = CHAIN_PATTERNS.get(ck, {})
            # remove any patterns that are already present in shared patterns (by regex string)
            chain_only = {p: name for p, name in chain_specific.items() if p not in SHARED_PATTERNS}
            combined = dict(SHARED_PATTERNS)
            combined.update(chain_only)

            CHAIN_COMPILED[ck] = {re.compile(p, re.IGNORECASE): name for p, name in combined.items()}
            # spin up threads for this chain
            for _ in range(max(1, args.threads)):
                t = threading.Thread(target=worker, args=(max(1, args.autosave), password, stop_flag, processed_counter, hits_per_label, lock, found_wallets, args.dry_run, args.max_hits_per_label, args.verbose, ck, mod), daemon=True)
                t.start()
                threads.append(t)

        # dashboard state
        recent_lines = []          # list of (label, addr, ts)
        label_last_seen = {}
        rate_window = deque(maxlen=RATE_SMOOTH_SECONDS)  # last N per-second samples
        last_rate_sample_time = time.time()
        last_rate_sample_count = 0

        # layout: header (fixed), body split left/right
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body")
        )
        layout["body"].split_row(Layout(name="left"), Layout(name="right"))

        prev_hits_snapshot = {}
        last_refresh_time = 0.0
        last_header_update = 0.0
        last_html_write = 0.0

        # initialize session tallies for active chains only
        session_tally = {ck: 0 for ck in active_chain_keys}

        with Live(layout, refresh_per_second=LIVE_REFRESH_PER_SEC, transient=False) as live:
            # initial header
            header_text = Text.assemble(
                (" Vanity Generator ", "bold white on dark_green"),
                ("  "),
                (f"Patterns: {len(PATTERNS)}", "bold"),
                ("  "),
                (f"Threads: {args.threads}",),
                ("  "),
                (f"Autosave: {args.autosave}",),
                ("  "),
                (f"Mnemonic: {MNEMONIC_WORDS} words",),
                ("  "),
                (f"[DRY-RUN]" if args.dry_run else "")
            )
            layout["header"].update(Panel(Align.left(header_text), padding=(0,1), border_style="green"))

            # initial panels
            layout["left"].update(Panel(Text("No matches yet"), title="Found wallets (latest)", border_style="bright_blue", padding=(1,1)))
            layout["right"].update(Panel(Text("No hits yet"), title="Tally", border_style="bright_magenta", padding=(1,1)))

            live.refresh()

            while True:
                time.sleep(0.03)
                now = time.time()

                # sample rate once per second
                if now - last_rate_sample_time >= 1.0:
                    with lock:
                        count_now = processed_counter["count"]
                    rate_sample = max(0, count_now - last_rate_sample_count)
                    # keep window length RATE_SMOOTH_SECONDS
                    rate_window.append(rate_sample)
                    # maintain as per-second samples for sparkline
                    last_rate_sample_count = count_now
                    last_rate_sample_time = now

                # consume found wallet events (main triggers)
                new_found = False
                with lock:
                    while found_wallets:
                        chain_key, lbl, addr, ts, wallet_obj = found_wallets.pop(0)
                        recent_lines.append((f"{chain_key}:{lbl}", addr, ts))
                        label_last_seen[f"{chain_key}:{lbl}"] = ts
                        # update session tally for the chain and all-time index
                        session_tally[chain_key] = session_tally.get(chain_key, 0) + 1
                        with ALL_TIME_LOCK:
                            ALL_TIME_HITS[f"{chain_key}:{lbl}"] = ALL_TIME_HITS.get(f"{chain_key}:{lbl}", 0) + 1
                        logging.info("Found %s | %s | %s", chain_key, lbl, addr)
                        if len(recent_lines) > RECENT_SHOW_MAX:
                            recent_lines = recent_lines[-RECENT_SHOW_MAX:]
                        new_found = True
                    hits_now = hits_per_label.copy()

                # Decide whether to update header/body
                body_changed = new_found or (hits_now != prev_hits_snapshot)
                header_changed = (now - last_header_update) >= HEADER_REFRESH_INTERVAL

                if body_changed or header_changed:
                    # Update header (sparklines & processed) on header_changed
                    if header_changed:
                        spark = sparkline_from_list(rate_window, width=30)
                        with lock:
                            proc_now = processed_counter["count"]
                        header_text = Text.assemble(
                            (" Vanity Generator ", "bold white on dark_green"),
                            ("  "),
                            (f"Patterns: {len(PATTERNS)}", "bold"),
                            ("  "),
                            (f"Threads: {args.threads}",),
                            ("  "),
                            (f"Autosave: {args.autosave}",),
                            ("  "),
                            (f"Mnemonic: {MNEMONIC_WORDS} words",),
                            ("  "),
                            ("Processed: ", "yellow"),
                            (str(proc_now), "bold"),
                            ("  "),
                            (spark, "cyan"),
                            ("  "),
                            (f"[DRY-RUN]" if args.dry_run else "")
                        )
                        layout["header"].update(Panel(Align.left(header_text), padding=(0,1), border_style="green"))
                        last_header_update = now

                    # Update body only when body_changed
                    if body_changed:
                        # Left panel: newest-first, full addresses, ease-out fade
                        left = Text()
                        tail = recent_lines[-RECENT_SHOW_MAX:] if recent_lines else []
                        for lbl_combined, addr, ts in reversed(tail):
                            age = now - ts
                            t = min(max(age / HIGHLIGHT_SECONDS, 0.0), 1.0)
                            t_eased = ease_out(t)
                            color = interpolate_hex_color(COLOR_NEW, COLOR_OLD, t_eased)
                            star = "★ " if age <= HIGHLIGHT_SECONDS else "  "
                            chain_key, label_only = lbl_combined.split(":", 1) if ":" in lbl_combined else ("", lbl_combined)
                            display_label = f"{chain_key}:{label_only}"
                            if age <= HIGHLIGHT_SECONDS:
                                left.append(star, style=f"{color} bold")
                                left.append(f"[{display_label}] ", style="bold cyan")
                                left.append(addr + "\n", style=f"monospace {color} bold")
                            else:
                                left.append(star)
                                left.append(f"[{display_label}] ", style="cyan")
                                left.append(addr + "\n", style=f"monospace {color}")
                        if not tail:
                            left.append("No matches yet", style="dim")
                        layout["left"].update(Panel(left, title="Found wallets (latest) — newest at top (click HTML to copy)", border_style="bright_blue", padding=(1,1)))

                        # Right panel: tally table (only for active chains)
                        table = Table(expand=True, show_edge=False, pad_edge=False)
                        table.add_column("Chain", style="magenta", no_wrap=True)
                        table.add_column("Session", justify="right", style="bold")
                        table.add_column("All-time", justify="right")
                        table.add_column("Last seen", justify="right", style="dim")

                        with ALL_TIME_LOCK:
                            all_time_snapshot = dict(ALL_TIME_HITS)

                        # Active chains
                        for ck in sorted(session_tally.keys()):
                            s = session_tally.get(ck, 0)
                            # For all-time we show total per-label aggregated — easier to show per-label in table_rows/HTML
                            # Here show a simple sum of hits for labels that were matched by this chain in-memory (approx)
                            a = sum(all_time_snapshot.get(lbl, 0) for lbl in all_time_snapshot.keys())
                            last_ts = None
                            # find most recent label for that chain in label_last_seen:
                            for k, v in label_last_seen.items():
                                if k.startswith(f"{ck}:"):
                                    last_ts = v
                                    break
                            last_seen_str = time_ago_seconds(last_ts, now) if last_ts is not None else "—"
                            color = "green" if ck == "sol" else ("yellow" if ck == "eth" else "cyan")
                            table.add_row(f"[{color}]{ck.upper()}[/{color}]", str(s), str(a), last_seen_str)

                        right_title = f"Tally — Active chains: {len(session_tally)}"
                        layout["right"].update(Panel(table, title=right_title, border_style="bright_magenta", padding=(1,1)))

                        # write HTML snapshot (body changed) & ensure we write periodically too
                        try:
                            # Build friendly table rows and recent rows for HTML
                            keys = sorted(set(list(hits_now.keys()) + list(all_time_snapshot.keys())),
                                          key=lambda k: (-hits_now.get(k, 0), -all_time_snapshot.get(k, 0), k))
                            table_rows = []
                            for k in keys:
                                s = hits_now.get(k, 0)
                                a = all_time_snapshot.get(k, 0)
                                last_ts = label_last_seen.get(k)
                                last_seen_str = time_ago_seconds(last_ts, now) if last_ts is not None else "—"
                                table_rows.append((k, s, a, last_seen_str))
                            recent_rows = []
                            for lblc, addr, ts in reversed(recent_lines[-RECENT_SHOW_MAX:]):
                                age = now - ts
                                t = min(max(age / HIGHLIGHT_SECONDS, 0.0), 1.0)
                                t_eased = ease_out(t)
                                color = interpolate_hex_color(COLOR_NEW, COLOR_OLD, t_eased)
                                recent_rows.append((lblc, addr, color, time_ago_seconds(ts, now)))
                            header_plain = f"Patterns: {len(PATTERNS)} | Threads: {args.threads} | Autosave: {args.autosave} | Processed: {processed_counter['count']}"
                            spark = sparkline_from_list(rate_window, width=30)
                            html = build_html_snapshot(header_plain, table_rows, recent_rows, spark, datetime.now(timezone.utc).isoformat())
                            atomic_write_bytes(HTML_DASH_PATH, html)
                        except Exception:
                            logging.exception("Failed writing HTML snapshot")

                        prev_hits_snapshot = hits_now

                    # refresh once for whatever changed
                    live.refresh()
                    last_refresh_time = now

                # Independent periodic HTML writer to keep ages fresh even if no body change
                last_html_write = maybe_write_html_snapshot_atomic(
                    lock=lock,
                    recent_lines=recent_lines,
                    hits_now_local=hits_now,
                    label_last_seen_local=label_last_seen,
                    rate_window_local=rate_window,
                    processed_counter_local=processed_counter,
                    patterns_count=len(PATTERNS),
                    threads_count=args.threads,
                    autosave_flag=args.autosave,
                    mnemonic_words=MNEMONIC_WORDS,
                    html_path=HTML_DASH_PATH,
                    last_html_write_ref=last_html_write,
                    html_interval=HTML_REFRESH_INTERVAL
                )

    except KeyboardInterrupt:
        try:
            print("\n[yellow]Stopping (keyboard interrupt)...[/yellow]")
        except Exception:
            pass
        stop_flag["stop"] = True
        for t in threads:
            try:
                t.join(timeout=5)
            except Exception:
                pass
        try:
            with ALL_TIME_LOCK:
                write_index_atomic(ALL_TIME_HITS)
        except Exception:
            logging.exception("Failed to write index on shutdown")
        try:
            cleanup_locks()
        except Exception:
            pass
        reset_terminal_colors()
        print(f"[cyan]HTML snapshot available:[/cyan] {HTML_DASH_PATH}")
    except Exception:
        try:
            reset_terminal_colors()
        except Exception:
            pass
        logging.exception("Main loop exception")
        print("[red]Unexpected error - check log.[/red]")
        try:
            stop_flag["stop"] = True
            for t in threads:
                try:
                    t.join(timeout=2)
                except Exception:
                    pass
            with ALL_TIME_LOCK:
                write_index_atomic(ALL_TIME_HITS)
            cleanup_locks()
        except Exception:
            pass
    finally:
        try:
            reset_terminal_colors()
        except Exception:
            pass
        try:
            if 'stop_flag' in locals():
                stop_flag["stop"] = True
            if 'threads' in locals():
                for t in threads:
                    try:
                        t.join(timeout=1)
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            with ALL_TIME_LOCK:
                write_index_atomic(ALL_TIME_HITS)
        except Exception:
            pass
        try:
            cleanup_locks()
        except Exception:
            pass


if __name__ == "__main__":
    main()
