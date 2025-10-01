# Vanity-SET  
_Vanity Address Generator for Solana, Ethereum, and TON_

---

## 🧭 Quick Navigation
- [Overview](#-overview)
- [Features](#-features)
- [Installation](#%EF%B8%8F-installation)
- [Configuration](#%EF%B8%8F-configuration)
- [Usage](#%EF%B8%8F-usage)
- [Project Structure](#-project-structure)
- [Security Notes](#-security--operational-notes)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)
- [Credits](#-credits)
 
---

## 📖 Overview

**Vanity-SET** (Sol / Eth / Ton) is a high‑performance multi-chain vanity address generator written in Python by Randy420.  
It lets you search for addresses that match **custom regular expressions** (shared across chains or chain-specific).  
Designed for speed, modularity, and extensibility.

Supported chains:
- **Solana (SOL)**
- **Ethereum / EVM (ETH)**
- **TON (TON)**

---

## ⚡ Features

- Simultaneous multi-chain search (`--chain all`).
- Shared + per-chain **regex rule sets**.
- Encrypted key storage.
- Threaded processing for performance.
- Clean, colorized terminal output (via `rich`).
- Configurable runtime via `config/settings.py`.
- Optional limit per label (avoid unbounded growth).

---

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/SolSpliff/Vanity-SET.git
cd Vanity-SET
```

### 2. Python Version
Use **Python 3.11+** (3.10 may work but 3.11 is what CI targets).

Check version:
```bash
python --version
```

If `python` maps to 2.x on Linux:
```bash
python3 --version
```

### 3. Install Dependencies

If the repo ships a requirements file (recommended):
```bash
pip install -r dependency-installs/requirements.txt
```

Typical dependencies include (for reference only):
```
pyinstaller
rich
mnemonic
pynacl
base58
cryptography
tonsdk
eth-account
web3
pwinput
```

(Do NOT manually install if you already used the requirements file.)

### 4. (Optional) Create a Virtual Environment
```bash
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# or
.\.venv\Scripts\activate       # Windows
pip install -r dependency-installs/requirements.txt
```

---

## ⚙️ Configuration

All configuration lives under [`config/`](./config).

### 1. Regex Rule Files

You control search logic via JSON lists of pattern objects or strings (depending on implementation).  
Current convention (recommended): **list of objects** with explicit labels.

Example (`config/regex.eth.json`):
```json
[
  "Regex": "file name",
  "^0xdead.*": "0xdead",
  ".*beef$": "beef"
]
```

Shared rules (apply to all chains):
- `regex.shared.json`

Per‑chain rules:
- `regex.sol.json`
- `regex.eth.json`
- `regex.ton.json`

> ```json
> [
>   "regex": "file name"
>   "^0xdead.*": "dead", # regex | name
>   ".*beef$": "beef"
> ]
> ```


### 2. Settings

Edit [`config/settings.py`](./config/settings.py). Example (illustrative only):
```python
THREADS = 4
SAVE_KEYS = True
AUTOSAVE = 1              # 1 = enabled, 0 = disabled
MNEMONIC_WORDS = 24       # 12|24 -> 24 is standard and more secure... use 12 at your own risk.
MAX_HITS_PER_LABEL = 25
VERBOSE = False
```

### 3. Encryption / Key Handling

The tool encrypts found keys & phrases using a passphrase prompt... ensure:
- You use a **strong passphrase** (length > 12, mix of classes).
- You store decrypted keys securely and NEVER share/commit them.

---

## ▶️ Usage

From repository root:
```bash
python vanity.py [OPTIONS]
```

### Core Options

| Option | Description |
|--------|-------------|
| `--chain {sol,eth,ton,all}` | Target a single chain or all simultaneously. |
| `--allchains` | Alias for `--chain all`. |
| `--threads N` | Override default thread count. |
| `--autosave {0,1}` | Enable/disable automatic encrypted saving. |
| `--mnemonic-words {12,24}` | Mnemonic length (if supported (ton wont accept 12)). |
| `--max-hits-per-label N` | Cap saved hits per label (0 or negative = unlimited). |
| `--decrypt [FILE/ALL]` | Decrypt saved encrypted key files. |
| `--dry-run` | Test matching without saving. |
| `--show-index` | Show metadata / hit index then exit. |
| `--verbose` | Verbose logging. |
| `--help` | Show help text. |

### Examples

Generate only Ethereum:
```bash
python vanity.py --chain eth
```

All chains, 8 threads:
```bash
python vanity.py --chain all --threads 8
```

Dry run shared + per-chain patterns (no saves):
```bash
python vanity.py --chain all --dry-run
```

Decrypt everything:
```bash
python vanity.py --decrypt
```

---

## 📂 Project Structure

```
Vanity-SET/
├── vanity.py                  # Main entrypoint
├── __init__.py
├── config/
│   ├── regex.shared.json
│   ├── regex.sol.json
│   ├── regex.eth.json
│   ├── regex.ton.json
│   └── settings.py
├── chains/                    # Chain-specific helpers/modules
├── dependency-installs/
│   └── requirements.txt
├── docs/                      # Documentation (optional)
├── vane/                      # Generated
│   ├── dashboard.html         # Session tracker
│   ├── kdf_salt               # Salt for encryption
│   ├── vanity.log             # log files
│   └── sol/eth/ton            # folders generated when you generate wallets for a chain
│       └── encrypted wallets  # encrypted wallets & phrases
├── LICENSE
└── README.md
```

---

## 🧪 Tips

- Run from repo root (same folder as `vanity.py`).
- Keep regex JSON valid (no trailing commas, proper quotes).
- Use fewer, more specific patterns for speed.
- Increase `THREADS` cautiously—diminishing returns above CPU core count.
- Use `--dry-run` to verify regex quality before long sessions.
- Periodically back up encrypted key files.
- If packaging with PyInstaller, update regex/config before building.

---

## 🛠️ Building a Standalone Binary (Optional)

The project can be bundled via PyInstaller (see CI workflow for reference):
```bash
pip install pyinstaller
pyinstaller --onefile vanity.py
```

To include data directories (manual example):
```bash
# Linux/macOS
pyinstaller --onefile \
  --add-data "config:config" \
  --add-data "dependency-installs:dependency-installs" \
  vanity.py

# Windows (note the semicolons)
pyinstaller --onefile ^
  --add-data "config;config" ^
  --add-data "dependency-installs;dependency-installs" ^
  vanity.py
```

Artifacts will appear in `dist/`.

---

## 🔐 Security & Operational Notes

- DO NOT use this on production or high-value systems without review.
- Generated mnemonics/private keys are sensitive—treat them like real wallet seeds.
- Avoid running on untrusted machines (e.g., shared VPS, compromised OS).
- Always verify source integrity (Git history, commit signatures if available).
- Consider air‑gapped generation for high-value addresses, then import offline results.

---

## 🧩 Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| No matches after long run | Patterns too strict | Simplify regex; test with `--dry-run` |
| PyInstaller missing files | Wrong `--add-data` syntax | Use `:` (Unix) or `;` (Windows) |
| Slow performance | Too many threads or I/O bound | Reduce threads; profile patterns |
| JSON decode error | Malformed regex JSON | Validate with `python -m json.tool file.json` |
| Encrypted file won't decrypt | Wrong passphrase | Retype carefully (case-sensitive) |

---

## 📜 License

Released under the [MIT License](./LICENSE).  
You are free to use, modify, and distribute with attribution.

---

## 💡 Credits

Created by Randy420 with ❤️ for the Web3 community.  
Supports **Solana, Ethereum, TON** out of the box.  
Part of ongoing experimentation ahead of a future SOL token concept (utility/meme).

Questions / ideas / contributions welcome.  
Telegram: https://t.me/Randy4_20

Special thanks to waruhachi for updating the readme && actually making the workflows... well, work.

---

## 🙌 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit changes: `git commit -m "feat: add X"`
4. Push: `git push origin feat/my-feature`
5. Open a Pull Request

Please lint / format if a style config is present.

---

## 🗺️ Roadmap (Potential Ideas)

- GPU acceleration (if feasible)
- Web UI wrapper
- Docker container packaging
- Pattern scoring / regex benchmarking
- Progress metrics (hits per second per chain)
- Structured logging / JSON output mode

> Open an issue if you'd like to help on any of these.

---

Enjoy generating those custom prefixes & suffixes responsibly!
