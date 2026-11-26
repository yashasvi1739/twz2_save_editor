# The Walking Zombie 2 Save Editor

Python utilities for decrypting, parsing, validating, and re-encrypting *The Walking Zombie 2* Android save files (`save.bin`).

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

### Prerequisites: Copy `base.apk` and `save.bin`

Copy both files from your Android device into your working directory using either a file manager or `adb`:

1. **`base.apk` (for key extraction):**
   - **Android 11+ path (accessible via ZArchiver with Shizuku, or root):**
     `/data/app/~~<random_hash>==/com.aldagames.zombieshooter-<random_hash>==/base.apk`
   - **Android 10 and older path:**
     `/data/app/com.aldagames.zombieshooter-<random_hash>/base.apk`
   - **Alternatives:** Export `base.apk` using an APK extractor app (e.g., MT Manager, ZArchiver, or APK Extractor), or pull it via `adb`:
     ```bash
     # Find the exact APK path on your device
     adb shell pm path com.aldagames.zombieshooter

     # Copy the path ending in base.apk (without the "package:" prefix) and pull it
     adb pull /data/app/~~<hash>==/com.aldagames.zombieshooter-<hash>==/base.apk base.apk
     ```

2. **`save.bin` (your game save file):**
   - **Manual path:**
     `/storage/emulated/0/Android/data/com.aldagames.zombieshooter/files/save.bin`
     *(On Android 11+, accessing `Android/data/` requires a file manager with Shizuku/SAF support such as ZArchiver or MT Manager.)*
   - **Via `adb`:**
     ```bash
     adb pull /storage/emulated/0/Android/data/com.aldagames.zombieshooter/files/save.bin save.bin
     ```
   - **Always keep a backup copy** of your original `save.bin` before editing.

### 1. Decrypt `save.bin`
With `save.bin` and `base.apk` in your working directory, run:

```bash
python3 Decrypt/decrypt_to_json.py
```

- **Input:** `save.bin` + `base.apk`
- **Output:** `save_decrypted.json`

### 2. Convert to Editable JSON
Parse the raw decrypted stream into a structured JSON file:

```bash
python3 Decrypt/clean_decrypted_json.py
```

- **Input:** `save_decrypted.json`
- **Output:** `save_clean.json`

Edit only the values inside the `"data"` object (such as `UserName`, `Level`, `Xp`, `CoinsGold`, `CoinsSilver`, `Gas`, `FreeSkillsPoints`, `FreePerksPoints`).
**Do not modify `"_meta"`**—it preserves byte-level formatting so unchanged fields are restored verbatim.

### 3. Validate Your Edits
Check your edited JSON for syntax, type safety, and binary rebuild compatibility:

```bash
python3 Encrypt/check_edited_json.py
```

- Press **Enter** at the prompt to validate `save_clean.json` (or enter a custom path).

### 4. Re-encrypt to `save.bin`
Rebuild the binary save and encrypt it with 3DES-ECB (PKCS#7 padding):

```bash
python3 Encrypt/encrypt_save.py
```

- Press **Enter** at both prompts to read `save_clean.json` and output `save.bin`.
- If `save.bin` already exists (and no `.bak` exists yet), a `save.bin.bak` backup is created automatically.

### 5. Restore `save.bin` to Your Device
Close *The Walking Zombie 2* completely (swipe it from Recent Apps or force-stop it so the background process doesn't overwrite your edited file on autosave), then copy the newly encrypted `save.bin` back to your phone:

- **Manual path:**
  `/storage/emulated/0/Android/data/com.aldagames.zombieshooter/files/save.bin`
- **Via `adb`:**
  ```bash
  adb shell am force-stop com.aldagames.zombieshooter
  adb push save.bin /storage/emulated/0/Android/data/com.aldagames.zombieshooter/files/save.bin
  ```
