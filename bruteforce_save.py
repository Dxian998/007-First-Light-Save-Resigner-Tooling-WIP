import os
import struct
import sys
import time
import zlib

def crack_index_save(filepath):
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        return None
        
    with open(filepath, "rb") as f:
        ciphertext = f.read()
        
    if len(ciphertext) < 8:
        print("[ERROR] File is too short to be a valid index.save.")
        return None
        
    print(f"Loaded ciphertext: {len(ciphertext)} bytes.")
    print("Detected index.save format. Initiating instant zero-cost XOR key reconstruction...")
    
    start_time = time.time()
    
    key = bytes([
        ciphertext[0] ^ 0x03,
        ciphertext[1] ^ 0x00,
        ciphertext[2] ^ 0x00,
        ciphertext[3] ^ 0x00,
        0x01, 0x00, 0x10, 0x01
    ])
    
    decrypted_data = bytes(c ^ key[i % 8] for i, c in enumerate(ciphertext))
    
    if b"SSaveGameHeader" in decrypted_data:
        elapsed = time.time() - start_time
        steam_id = struct.unpack("<Q", key)[0]
        print(f"\n[SUCCESS] Key cracked in {elapsed:.6f} seconds!")
        print(f"  Cracked SteamID64: {steam_id}")
        print(f"  Cracked XOR Key:   {key.hex(' ')}")
        
        out_path = filepath + ".decrypted"
        with open(out_path, "wb") as out_f:
            out_f.write(decrypted_data)
        print(f"  Saved decrypted index -> {os.path.basename(out_path)}")
        return steam_id
    else:
        print("\n[FAILED] Instant key reconstruction failed to yield a valid SSaveGameHeader.")
        return None

def bruteforce_data_save(filepath):
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        return None
        
    with open(filepath, "rb") as f:
        ciphertext = f.read()
        
    if len(ciphertext) < 32:
        print("[ERROR] File is too short to be a valid data.save.")
        return None
        
    print(f"Loaded ciphertext: {len(ciphertext)} bytes.")
    print("Initiating accelerated zlib-constrained key-space reduction...")
    
    start_time = time.time()
    b0 = ciphertext[0] ^ 0x78
    valid_flgs = [0x01, 0x5E, 0x9C, 0xDA]
    b1_candidates = [ciphertext[1] ^ flg for flg in valid_flgs]
    
    print(f"  Key Byte 0 resolved to: 0x{b0:02X}")
    print(f"  Key Byte 1 candidates:  {', '.join(f'0x{c:02X}' for c in b1_candidates)}")
    print("  Testing remaining 16-bit key space (262,144 combinations)...")

    header_chunk = ciphertext[:16]
    found_key = None
    tests_run = 0
    
    for b1 in b1_candidates:
        for b2 in range(256):
            for b3 in range(256):
                tests_run += 1
                key = bytes([b0, b1, b2, b3, 0x01, 0x00, 0x10, 0x01])
                dec_header = bytes(c ^ key[i % 8] for i, c in enumerate(header_chunk))
                cmf = dec_header[0]
                flg = dec_header[1]
                if cmf == 0x78 and (cmf * 256 + flg) % 31 == 0:
                    try:
                        verify_chunk = bytes(c ^ key[i % 8] for i, c in enumerate(ciphertext[:128]))
                        decompressor = zlib.decompressobj()
                        decompressor.decompress(verify_chunk)
                        full_decrypted = bytes(c ^ key[i % 8] for i, c in enumerate(ciphertext))
                        decompressed = zlib.decompress(full_decrypted)
                        found_key = key
                        elapsed = time.time() - start_time
                        steam_id = struct.unpack("<Q", key)[0]
                        print(f"\n[SUCCESS] Key cracked in {elapsed:.4f} seconds after {tests_run} tests!")
                        print(f"  Cracked SteamID64: {steam_id}")
                        print(f"  Cracked XOR Key:   {key.hex(' ')}")
                        print(f"  Decompressed Size: {len(decompressed)} bytes")

                        if len(decompressed) >= 32:
                            head_len = struct.unpack_from("<I", decompressed, 4)[0] & 0x3FFFFFFF
                            if head_len < 100:
                                head_str = decompressed[8:8+head_len].decode('latin-1', errors='replace')
                                print(f"  Save Data Class:   '{head_str}'")
                        out_path = filepath + ".decrypted"
                        with open(out_path, "wb") as out_f:
                            out_f.write(decompressed)
                        print(f"  Saved raw decompressed file -> {os.path.basename(out_path)}")
                        return steam_id
                    except Exception:
                        pass
                        
    elapsed = time.time() - start_time
    print(f"\n[FAILED] Brute-force completed in {elapsed:.4f} seconds after {tests_run} tests. No key found.")
    return None

def main():
    if len(sys.argv) < 2:
        print("007 First Light (Knight) Save Bruteforcer")
        print("=============================================")
        print("Usage: python bruteforce_save.py <path/to/save_file>")
        print("Example: python bruteforce_save.py data.save")
        print("Example: python bruteforce_save.py index.save")
        sys.exit(1)
        
    filepath = sys.argv[1]
    filename = os.path.basename(filepath).lower()
    
    if "index.save" in filename:
        crack_index_save(filepath)
    else:
        bruteforce_data_save(filepath)

if __name__ == "__main__":
    main()
