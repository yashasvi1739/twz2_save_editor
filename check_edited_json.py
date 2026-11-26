import json
import os
import struct
import sys

def encode_field(val, finfo):
    mode = finfo.get("mode", "raw_hex")
    orig_val = finfo.get("orig_val")
    orig_hex = finfo.get("raw_hex", "")

    # Unchanged value -> restore exact original bytes
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

    # If user edited a hex string directly
    if isinstance(val, str):
        clean_hex = val.strip().removeprefix("0x")
        if len(clean_hex) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean_hex):
            return bytes.fromhex(clean_hex)

    # If user edited a parsed JSON structure inside a block with prefix/suffix
    if orig_hex:
        raw_orig = bytes.fromhex(orig_hex)
        for opener, closer in (("{", "}"), ("[", "]")):
            ob = opener.encode("ascii")
            cb = closer.encode("ascii")
            fo = raw_orig.find(ob)
            lc = raw_orig.rfind(cb)
            if fo != -1 and lc != -1 and lc >= fo:
                return raw_orig[:fo] + json.dumps(val, separators=(",", ":")).encode("utf-8") + raw_orig[lc + 1 :]
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

def check_json(path):
    errors = []
    warnings = []

    if not path:
        return False, ["No file path provided."], []

    path = os.path.expanduser(path.strip().strip('"').strip("'"))

    if not os.path.exists(path):
        return False, [f"File not found: {path}"], []

    if not os.path.isfile(path):
        return False, [f"Not a regular file: {path}"], []

    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        return False, [f"Invalid JSON syntax in '{path}': {e}"], []

    if not isinstance(obj, dict) or "_meta" not in obj or "data" not in obj:
        errors.append("Top-level JSON must be an object containing '_meta' and 'data'.")
        return False, errors, warnings

    meta = obj["_meta"]
    data = obj["data"]
    order = meta.get("order", [])
    fields_meta = meta.get("fields", {})

    if not isinstance(order, list) or not isinstance(fields_meta, dict) or not isinstance(data, dict):
        errors.append("Malformed '_meta' or 'data' structure.")
        return False, errors, warnings

    for name in order:
        if name not in data:
            errors.append(f"Field '{name}' listed in _meta.order is missing from data.")
            continue
        finfo = fields_meta.get(name, {})
        mode = finfo.get("mode", "")
        val = data[name]

        if mode in ("tag07_i32", "tag04_i32", "u48_be", "tag08_i64"):
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                errors.append(f"Field '{name}' ({mode}) expects an integer, got {type(val).__name__} ({val!r}).")
        elif mode == "tag06_f32":
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                errors.append(f"Field '{name}' ({mode}) expects a number, got {type(val).__name__} ({val!r}).")
        elif mode == "tag02_bool":
            if not isinstance(val, bool):
                errors.append(f"Field '{name}' ({mode}) expects true/false, got {type(val).__name__} ({val!r}).")
        elif isinstance(val, str) and mode == "raw_hex":
            h = val.strip().removeprefix("0x")
            if len(h) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in h):
                errors.append(f"Field '{name}' (raw_hex) has invalid hex string: {val!r}")

    if not errors:
        try:
            rebuilt = rebuild_plaintext(obj)
            changed = [
                k for k in order
                if data[k] != fields_meta.get(k, {}).get("orig_val")
            ]
            print(f"File checked      : {path}")
            print(f"Rebuilt byte size : {len(rebuilt)} bytes")
            print(f"Modified fields   : {len(changed)}{' -> ' + str(changed) if changed else ''}")
        except Exception as e:
            errors.append(f"Rebuild failed: {e}")

    return len(errors) == 0, errors, warnings

def prompt_for_file():
    try:
        user_input = input("Enter path to JSON file to check [save_clean.json]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    return user_input if user_input else "save_clean.json"

if __name__ == "__main__":
    target = prompt_for_file()
    ok, errs, warns = check_json(target)
    for w in warns:
        print(f"[WARN] {w}")
    for e in errs:
        print(f"[ERROR] {e}")
    if ok:
        print(f"CHECK PASSED: '{target}' is valid and ready to encrypt.")
        sys.exit(0)
    else:
        print(f"CHECK FAILED: fix the errors above in '{target}' before encrypting.")
        sys.exit(1)
