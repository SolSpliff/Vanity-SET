# Vanity S.E.T.  
_Vanity Address Generator for Solana, Ethereum, and Ton_

---

## 📖 Overview

**Vanity S.E.T.** (Sol, Eth, Ton) is a multi-chain vanity address generator written in Python.  
It allows you to generate wallet addresses that **match custom regex patterns** you define.  
The tool is designed for speed, flexibility, and configurability, with support for **shared regex rules** as well as **chain-specific regex rules**.

Supported blockchains:
- **Solana (SOL)**
- **Ethereum (ETH)**
- **Ton (TON)**

---

## ⚡ Features

- Generate addresses on **multiple chains simultaneously**.
- Match against:
  - **Shared regex rules** (apply to all chains).
  - **Per-chain regex rules** (unique to SOL/ETH/TON).
- Customizable output and runtime behavior through `settings.py`.
- Secure passphrase input (masked with `*`).
- Colorized console output.
- Auto-migrates old config formats (`regex.chain.json` → per-chain JSONs).
- Graceful exit handling (resets console colors, cleans up locks).

---

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/vanity-set.git
cd vanity-set
```

### 2. Install Python
- **Windows:**  
  Download Python 3.10+ from [python.org](https://www.python.org/downloads/windows/).  
  During installation, **check "Add Python to PATH"**.

- **Linux/macOS:**  
  Most systems already include Python 3. Run:
  ```bash
  python3 --version
  ```

### 3. Install Dependencies
From the project root, run:
```bash
pip install -r requirements.txt
```

If you don’t have a `requirements.txt`, here are the core dependencies:
```bash
pip install mnemonic pwinput colorama rich
```

*(Other libraries may be added as your config expands.)*

---

## ⚙️ Configuration

All configs are located in the [`config/`](./config) directory.

### 1. Regex Files
You control how addresses are matched with regex JSONs:

- **Shared rules (all chains):**
  - `regex.shared.json`
- **Chain-specific rules:**
  - `regex.sol.json`
  - `regex.eth.json`
  - `regex.ton.json`

Each file must be **valid JSON** containing a list of regex strings.  
Example (`regex.eth.json`):
```json
[
  "^0xdead.*",
  ".*beef$"
]
```

> ⚠️ Make sure you use **valid JSON** — double quotes, no trailing commas.

### 2. Settings
Edit [`config/settings.py`](./config/settings.py) to tweak runtime options:
```python
# Example settings.py
THREADS = 4
SAVE_KEYS = True
OUTPUT_DIR = "output"
```

---

## ▶️ Usage

Run the program from the project root:

```bash
python vanity.py [OPTIONS]
```

### Arguments & Options

| Argument | Description |
|----------|-------------|
| `--sol`  | Enable Solana address generation. |
| `--eth`  | Enable Ethereum address generation. |
| `--ton`  | Enable Ton address generation. |
| `--all`  | Run all chains simultaneously. |
| `--threads N` | Set number of worker threads (default from `settings.py`). |
| `--output DIR` | Override the output directory. |
| `--regex FILE` | Use an alternate regex config file. |
| `--dry-run` | Test regex matching without generating keys. |
| `--help` | Show usage help. |

### Examples

Run Ethereum only:
```bash
python vanity.py --eth
```

Run all chains, 8 threads:
```bash
python vanity.py --all --threads 8
```

Use a custom regex file:
```bash
python vanity.py --eth --regex config/my.eth.regex.json
```

---

## 📂 Project Structure

```
vanity-set/
│
├── vanity.py              # Main entrypoint
├── config/                # Configuration files
│   ├── regex.shared.json
│   ├── regex.sol.json
│   ├── regex.eth.json
│   ├── regex.ton.json
│   └── settings.py
├── dependency-installs/   # Setup/installation scripts
├── vane/                  # Internal modules (chains, utils, etc.)
└── README.md              # This file
```

---

## 🧪 Tips

- Always run from the **project root** (same directory as `vanity.py`).
- If you see JSON parse warnings, fix your `regex.*.json` with proper JSON syntax.
- Use `Ctrl+C` to stop
- Generated keys/addresses will be saved in the output directory (`output/` by default).

---

## 📜 License

MIT License — free to use, modify, and share. See [LICENSE](./LICENSE) for details.

---

## 💡 Credits

Developed with ❤️ for the Web3 community.  
Supports **Solana, Ethereum, and Ton** out of the box.
Proof of concept work for my future SOL Token which will be dropping. Utility/Meme :)

hit me up on telegram if there are any questions, comments or suggestions... or simply put in reports/push updates.
https://t.me/Randy4_20