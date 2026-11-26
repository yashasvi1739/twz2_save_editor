import ctypes
import glob
import os
import struct
import sys
import zipfile

# --- 1. Initialize OpenSSL 3DES-ECB ---
libcrypto = None
for libname in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
    try:
        libcrypto = ctypes.CDLL(libname)
        break
    except OSError:
        continue

try:
    libcrypto.OSSL_PROVIDER_load.restype = ctypes.c_void_p
    libcrypto.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    libcrypto.OSSL_PROVIDER_load(None, b"legacy")
    libcrypto.OSSL_PROVIDER_load(None, b"default")
except Exception:
    pass

libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
libcrypto.EVP_des_ede3_ecb.restype = ctypes.c_void_p
libcrypto.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
libcrypto.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
libcrypto.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

TDES_ECB = libcrypto.EVP_des_ede3_ecb()

def dec_3des(key16, data):
    key24 = key16[:16] + key16[:8]
    ctx = libcrypto.EVP_CIPHER_CTX_new()
    libcrypto.EVP_DecryptInit_ex(ctx, TDES_ECB, None, key24, None)
    libcrypto.EVP_CIPHER_CTX_set_padding(ctx, 0)
    out = ctypes.create_string_buffer(len(data) + 16)
    outlen = ctypes.c_int(0)
    libcrypto.EVP_DecryptUpdate(ctx, out, ctypes.byref(outlen), data, len(data))
    libcrypto.EVP_CIPHER_CTX_free(ctx)
    return out.raw[: outlen.value]

with open("save.bin", "rb") as f:
    save_bytes = f.read()

def try_key_pair(label, part_a, part_b):
    base = "g852fa7sSSfasgsf"
    combos = [
        ("zip_ab", "".join(x + y for x, y in zip(part_a, base))[:10] + part_b),
        ("zip_ba", "".join(y + x for x, y in zip(part_a, base))[:10] + part_b),
        ("zip_b_first", "".join(x + y for x, y in zip(part_b, base))[:10] + part_a),
        ("concat_ab", (part_a + base)[:10] + part_b),
        ("direct_ab", part_a + part_b),
        ("direct_ba", part_b + part_a),
    ]
    for mode, key_str in combos:
        kb = key_str.encode("utf-8")
        if len(kb) < 16:
            kb = kb.ljust(16, b"\x00")
        kb = kb[:16]
        pt = dec_3des(kb, save_bytes[:64])
        last = dec_3des(kb, save_bytes[-8:])
        pad = last[-1]
        pad_ok = (1 <= pad <= 8) and all(b == pad for b in last[-pad:])
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in pt)
        if pad_ok and printable >= 40:
            print(f"\n[SUCCESS!] Asset={label} | Mode={mode} | KeyStr={key_str!r} | Key16={kb!r} | Pad={pad}")
            print(f"  First 64 bytes: {pt}")
            full = dec_3des(kb, save_bytes)[:-pad]
            with open("save_decrypted.json", "wb") as out_f:
                out_f.write(full)
            print(f"  --> Wrote {len(full)} decrypted bytes to save_decrypted.json!")
            return True
    return False

# --- 2. Pure-Python LZ4 Block Decompressor + UnityFS Unpacker ---
def lz4_decompress_block(src, uncompressed_size):
    dst = bytearray(uncompressed_size)
    ip = 0
    op = 0
    n = len(src)
    while ip < n:
        token = src[ip]
        ip += 1
        lit_len = token >> 4
        if lit_len == 15:
            while ip < n:
                b = src[ip]
                ip += 1
                lit_len += b
                if b != 255:
                    break
        if lit_len > 0:
            dst[op : op + lit_len] = src[ip : ip + lit_len]
            ip += lit_len
            op += lit_len
        if ip >= n or op >= uncompressed_size:
            break
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if offset == 0:
            break
        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while ip < n:
                b = src[ip]
                ip += 1
                match_len += b
                if b != 255:
                    break
        for _ in range(match_len):
            if op >= uncompressed_size:
                break
            dst[op] = dst[op - offset]
            op += 1
    return bytes(dst[:op])

def decompress_block(comp_data, uncomp_sz, flags):
    ctype = flags & 0x3F
    if ctype == 0:
        return comp_data
    if ctype in (2, 3):  # LZ4 / LZ4HC
        return lz4_decompress_block(comp_data, uncomp_sz)
    if ctype == 1:  # LZMA
        import lzma
        props = comp_data[:5]
        dict_size = struct.unpack("<I", props[1:5])[0]
        lc = props[0] % 9
        rem = props[0] // 9
        lp = rem % 5
        pb = rem // 5
        filt = [{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}]
        return lzma.decompress(comp_data[5:], format=lzma.FORMAT_RAW, filters=filt)
    raise ValueError(f"Unsupported UnityFS compression type {ctype}")

def unpack_unityfs(blob):
    pos = blob.find(b"\x00") + 1  # signature ("UnityFS\0")
    fmt_ver = struct.unpack_from(">I", blob, pos)[0]
    pos += 4
    pos = blob.find(b"\x00", pos) + 1  # unityVersion
    pos = blob.find(b"\x00", pos) + 1  # unityRevision
    total_sz, comp_info_sz, uncomp_info_sz, flags = struct.unpack_from(">QIII", blob, pos)
    pos += 20
    if fmt_ver >= 7:
        pos = (pos + 15) & ~15
    if (flags & 0x80) != 0:  # kArchiveBlocksInfoAtTheEnd
        info_comp = blob[-comp_info_sz:]
        data_pos = pos
    else:
        info_comp = blob[pos : pos + comp_info_sz]
        data_pos = pos + comp_info_sz
    if (flags & 0x200) != 0:  # kArchiveBlockInfoNeedPaddingAtStart
        data_pos = (data_pos + 15) & ~15

    info_raw = decompress_block(info_comp, uncomp_info_sz, flags)
    # Parse StorageBlocks + DirectoryInfo
    ipos = 16  # skip uncompressedDataHash
    block_cnt = struct.unpack_from(">I", info_raw, ipos)[0]
    ipos += 4
    blocks = []
    for _ in range(block_cnt):
        u_sz, c_sz, b_flags = struct.unpack_from(">IIH", info_raw, ipos)
        ipos += 10
        blocks.append((u_sz, c_sz, b_flags))

    node_cnt = struct.unpack_from(">I", info_raw, ipos)[0]
    ipos += 4
    nodes = []
    for _ in range(node_cnt):
        n_off, n_sz, n_flags = struct.unpack_from(">QQI", info_raw, ipos)
        ipos += 20
        n_end = info_raw.find(b"\x00", ipos)
        n_name = info_raw[ipos:n_end].decode("utf-8", errors="replace")
        ipos = n_end + 1
        nodes.append((n_name, n_off, n_sz))

    print(f"  Unpacking {len(blocks)} blocks into {len(nodes)} UnityFS entries...")
    unpacked = bytearray()
    cur = data_pos
    for u_sz, c_sz, b_flags in blocks:
        unpacked.extend(decompress_block(blob[cur : cur + c_sz], u_sz, b_flags))
        cur += c_sz

    return [(name, bytes(unpacked[off : off + sz])) for name, off, sz in nodes]

def read_aligned_str(buf, off):
    if off + 4 > len(buf):
        return None, off
    slen = struct.unpack_from("<i", buf, off)[0]
    if slen < 0 or slen > 256 or off + 4 + slen > len(buf):
        return None, off
    raw = buf[off + 4 : off + 4 + slen]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, off
    if any(ord(c) < 32 for c in text):
        return None, off
    next_off = off + 4 + ((slen + 3) & ~3)
    return text, next_off

apk_paths = sys.argv[1:] if len(sys.argv) > 1 else sorted(glob.glob("*.apk") + glob.glob("*.xapk"))
solved = False

for apk in apk_paths:
    with zipfile.ZipFile(apk, "r") as zf:
        if "assets/bin/Data/data.unity3d" not in zf.namelist():
            continue
        print(f"Decompressing assets/bin/Data/data.unity3d from {apk}...")
        u3d_blob = zf.read("assets/bin/Data/data.unity3d")
        entries = unpack_unityfs(u3d_blob)
        for ename, ebytes in entries:
            print(f"  Entry: {ename} ({len(ebytes):,} bytes)")
            sig = b"\x00" * 12 + b"\x01\x00\x00\x00"
            pos = 0
            while True:
                idx = ebytes.find(sig, pos)
                if idx == -1:
                    break
                pos = idx + 4
                if idx + 32 > len(ebytes):
                    continue
                file_id, path_id = struct.unpack_from("<iq", ebytes, idx + 16)
                if path_id == 0 or abs(file_id) > 100:
                    continue
                so_name, p1 = read_aligned_str(ebytes, idx + 28)
                if so_name is None:
                    continue
                s1, p2 = read_aligned_str(ebytes, p1)
                s2, _ = read_aligned_str(ebytes, p2) if s1 is not None else (None, p1)
                if s1 or s2:
                    print(f"    [{ename}] {so_name}: field1={s1!r}, field2={s2!r}")
                    if not solved and try_key_pair(so_name, s1 or "", s2 or ""):
                        solved = True
