# The Walking Zombie 2 Save Editor

Python utilities for decrypting, parsing, validating, and re-encrypting *The Walking Zombie 2* save files (`save.bin`).

## Requirements

- **Python 3.9+** (standard library only; no `pip` packages required)
- **OpenSSL (`libcrypto`)** — `decrypt_to_json.py` and `encrypt_save.py` call OpenSSL's 3DES-ECB cipher via `ctypes` (`libcrypto.so.3`, `libcrypto.so.1.1`, or `libcrypto.so`).
  - *Note:* Targets Linux/Unix shared libraries (`.so`). On OpenSSL 3.x, the scripts automatically attempt to load the `legacy` provider for 3DES support.
- **Game APK/XAPK** — Provide your own `base.apk` or `.xapk` locally for key extraction. Do **not** commit game binaries to GitHub.

## Repository Structure

```text
.
├── Decrypt/
│   ├── decrypt_to_json.py       # Extracts 3DES key from APK/XAPK and decrypts save.bin
│   └── clean_decrypted_json.py  # Parses raw decrypted data into editable JSON
└── Encrypt/
    ├── check_edited_json.py     # Validates edited JSON and dry-runs binary rebuild
    └── encrypt_save.py          # Rebuilds binary save and re-encrypts with 3DES-ECB
```

## Usage

### 1. Decrypt `save.bin`
Place `save.bin` and your `.apk` or `.xapk` in your working directory, then run:

```bash
# Auto-detects *.apk and *.xapk in the current directory
python3 Decrypt/decrypt_to_json.py

# Or pass one or more APK/XAPK paths explicitly
python3 Decrypt/decrypt_to_json.py path/to/base.apk
```

- **Input:** `save.bin` (in the current directory) + `.apk`/`.xapk`
- **Output:** `save_decrypted.json`

### 2. Convert to Editable JSON
Parse the raw decrypted stream into a structured JSON file:

```bash
python3 Decrypt/clean_decrypted_json.py
```

- **CLI Arguments:** None
- **Input:** `save_decrypted.json`
- **Output:** `save_clean.json`

Edit only the values inside the `"data"` object (such as `UserName`, `Level`, `Xp`, `CoinsGold`, `CoinsSilver`, `Gas`, `FreeSkillsPoints`, `FreePerksPoints`). **Do not modify `"_meta"`**—it preserves byte-level formatting so unchanged fields are restored verbatim.

### 3. Validate Your Edits
Check your edited JSON for syntax, type safety, and binary rebuild compatibility:

```bash
python3 Encrypt/check_edited_json.py
```

- **CLI Arguments:** None (interactive prompt)
  - `Enter path to JSON file to check [save_clean.json]:`
- **Exit Codes:** `0` if valid, `1` if errors are found.

### 4. Re-encrypt to `save.bin`
Rebuild the binary save and encrypt it with 3DES-ECB (PKCS#7 padding):

```bash
python3 Encrypt/encrypt_save.py
```

- **CLI Arguments:** None (interactive prompts)
  - `Enter path to JSON file to encrypt [save_clean.json]:`
  - `Enter output encrypted file path [save.bin]:`
- **Backup:** If the output file already exists (and no `.bak` exists yet), a `<output>.bak` backup is created automatically.
