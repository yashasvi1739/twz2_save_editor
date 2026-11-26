import ctypes
import json
import os
import shutil
import struct
import sys

KEY16 = b"7g38v5q2[fEG^emY"

libcrypto = None
for libname in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
    try:
        libcrypto = ctypes.CDLL(libname)
        break
    except OSError:
        continue

if libcrypto is None:
    print("[ERROR] Could not load OpenSSL libcrypto.")
    sys.exit(1)

try:
    libcrypto.OSSL_PROVIDER_load.restype = ctypes.c_void_p
    libcrypto.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    libcrypto.OSSL_PROVIDER_load(None, b"legacy")
    libcrypto.OSSL_PROVIDER_load(None, b"default")
except Exception:
    pass

libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
libcrypto.EVP_EncryptInit_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
libcrypto.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
libcrypto.EVP_EncryptUpdate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_char_p,
    ctypes.c_int,
]
libcrypto.EVP_EncryptFinal_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int),
]
libcrypto.EVP_des_ede3_ecb.restype = ctypes.c_void_p
TDES_ECB = libcrypto.EVP_des_ede3_ecb()


def encrypt_3des_pkcs7(key16, plaintext):
    key24 = key16[:16] + key16[:8]
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    libcrypto.EVP_EncryptInit_ex(ctx, TDES_ECB, None, key24, None)
    libcrypto.EVP_CIPHER_CTX_set_padding(ctx, 1)

    out = ctypes.create_string_buffer(len(plaintext) + 32)
    outlen1 = ctypes.c_int(0)
    outlen2 = ctypes.c_int(0)

    libcrypto.EVP_EncryptUpdate(ctx, out, ctypes.byref(outlen1), plaintext, len(plaintext))
    tail_ptr = ctypes.cast(ctypes.addressof(out) + outlen1.value, ctypes.c_char_p)
    libcrypto.EVP_EncryptFinal_ex(ctx, tail_ptr, ctypes.byref(outlen2))
    libcrypto.EVP_CIPHER_CTX_free(ctx)

    return out.raw[: outlen1.value + outlen2.value]


def encode_field(val, finfo):
    mode = finfo.get("mode", "raw_hex")
    orig_val = finfo.get("orig_val")
    orig_hex = finfo.get("raw_hex", "")

    if orig_hex and val == orig_val:
        return bytes.fromhex(orig_hex)

    if mode == "empty" or val is None:
        return b""
    if mode == "tag07_i32":
        return b"\x07" + struct.pack("<i", int(val)) + bytes.fromhex(finfo.get("tail_hex", ""))
    if mode == "tag04_i32":
        return b"\x04" + struct.pack("<i", int(val)) + bytes.fromhex(finfo.get("tail_hex", ""))
    if mode == "tag06_f32":
        return b"\x06" + struct.pack("<f", float(val)) + bytes.fromhex(finfo.get("tail_hex", ""))
    if mode == "tag02_bool":
        return b"\x02" + (b"\x01" if bool(val) else b"\x00") + bytes.fromhex(finfo.get("tail_hex", ""))
    if mode == "tag08_i64":
        return b"\x08" + struct.pack("<q", int(val)) + bytes.fromhex(finfo.get("tail_hex", ""))
    if mode == "u48_be":
        ival = int(val)
        if not (0 <= ival <= 0xFFFFFFFFFFFF):
            raise ValueError(f"Value out of 6-byte unsigned range: {ival}")
        return ival.to_bytes(6, "big")
    if mode.startswith("tag") and mode.endswith("_str1"):
        tag_byte = int(mode[3:5], 16)
        sbytes = str(val).encode("utf-8")
        return bytes([tag_byte, len(sbytes)]) + sbytes + bytes.fromhex(finfo.get("tail_hex", ""))

    if isinstance(val, str):
        clean_hex = val.strip().removeprefix("0x")
        if len(clean_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
            return bytes.fromhex(clean_hex)

    if orig_hex:
        raw_orig = bytes.fromhex(orig_hex)
        for opener, closer in (("{", "}"), ("[", "]")):
            ob = opener.encode("ascii")
            cb = closer.encode("ascii")
            fo = raw_orig.find(ob)
            lc = raw_orig.rfind(cb)
            if fo != -1 and lc != -1 and lc >= fo:
                return (
                    raw_orig[:fo]
                    + json.dumps(val, separators=(",", ":")).encode("utf-8")
                    + raw_orig[lc + 1 :]
                )
        return raw_orig

    raise ValueError(f"Cannot encode modified value for mode={mode!r}")


def rebuild_plaintext(clean_obj):
    meta = clean_obj["_meta"]
    data = clean_obj["data"]
    out = bytearray(bytes.fromhex(meta.get("header_hex", "")))
    for name in meta["order"]:
        out.extend(name.encode("utf-8"))
        out.extend(encode_field(data[name], meta["fields"][name]))
    return bytes(out)


def prompt_path(prompt_text, default_val):
    try:
        raw = input(prompt_text).strip().strip('"').strip("'")
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    return os.path.expanduser(raw) if raw else default_val


def main():
    json_path = prompt_path("Enter path to JSON file to encrypt [save_clean.json]: ", "save_clean.json")
    out_bin = prompt_path("Enter output encrypted file path [save.bin]: ", "save.bin")

    if not os.path.isfile(json_path):
        print(f"[ERROR] File not found: {json_path}")
        sys.exit(1)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            clean_obj = json.load(f)
    except Exception as e:
        print(f"[ERROR] Invalid JSON: {e}")
        sys.exit(1)

    try:
        plaintext = rebuild_plaintext(clean_obj)
        ciphertext = encrypt_3des_pkcs7(KEY16, plaintext)
    except Exception as e:
        print(f"[ERROR] Build/encrypt failed: {e}")
        sys.exit(1)

    if os.path.exists(out_bin) and not os.path.exists(out_bin + ".bak"):
        shutil.copy2(out_bin, out_bin + ".bak")
        print(f"Backed up existing {out_bin} -> {out_bin}.bak")

    with open(out_bin, "wb") as f:
        f.write(ciphertext)

    print(
        f"Encrypted {len(plaintext)} plaintext bytes -> {len(ciphertext)} bytes in {out_bin} ({len(ciphertext) // 8} blocks)"
    )


if __name__ == "__main__":
    main()
