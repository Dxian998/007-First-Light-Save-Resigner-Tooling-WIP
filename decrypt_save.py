import os
import struct
import sys
import zlib

KNOWN_SOURCE_SID = 76561198026925824

def detect_source_steam_id(index_path):
    target_path = index_path
    if not os.path.exists(target_path):
        target_path = index_path + ".backup"
        
    try:
        with open(target_path, "rb") as f:
            data = f.read()
        if len(data) >= 28:
            account_id = struct.unpack_from("<I", data, 24)[0]
            detected_sid = 76561197960265728 + account_id
            return detected_sid
    except Exception:
        pass
    return None


def decrypt_index_file(filepath, steam_sid):
    print(f"  Processing index.save:")
    with open(filepath, 'rb') as f:
        data = f.read()
        
    if len(data) < 8:
        print("    [ERROR] index.save file is too short.")
        return
        
    sid_bytes = struct.pack("<Q", steam_sid)
    decrypted_data = bytes(c ^ sid_bytes[i % 8] for i, c in enumerate(data))
    
    if b"SSaveGameHeader" in decrypted_data:
        print("    [OK] Decrypted header structure verified: Found 'SSaveGameHeader'")
        
    out_path = filepath + ".decrypted"
    with open(out_path, 'wb') as f:
        f.write(decrypted_data)
    print(f"    [SUCCESS] Dumped decrypted index raw payload -> {os.path.basename(out_path)}\n")


def decrypt_data_file(filepath, steam_sid):
    print(f"  Processing data.save:")
    with open(filepath, 'rb') as f:
        ciphertext = f.read()
        
    sid_bytes = struct.pack("<Q", steam_sid)
    decrypted_xor = bytes(c ^ sid_bytes[i % 8] for i, c in enumerate(ciphertext))
    
    try:
        decompressed_payload = zlib.decompress(decrypted_xor)
        print(f"    [OK] Decrypted and decompressed payload successfully ({len(decompressed_payload)} raw bytes).")
        
        if len(decompressed_payload) >= 32:
            head_len = struct.unpack_from("<I", decompressed_payload, 4)[0] & 0x3FFFFFFF
            if head_len < 100:
                head_str = decompressed_payload[8:8+head_len].decode('latin-1', errors='replace')
                print(f"    Save Data Class type: '{head_str}'")
                
        out_path = filepath + ".decrypted"
        with open(out_path, 'wb') as f:
            f.write(decompressed_payload)
        print(f"    [SUCCESS] Dumped decrypted raw save payload -> {os.path.basename(out_path)}\n")
        return True
    except Exception as e:
        print(f"    [ERROR] Decompression failed. The SteamID {steam_sid} may be incorrect, or the file is corrupted. {e}\n")
        return False


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    print("007 First Light (Knight) Inspector & Decrypter")
    print("==============================================")
    
    manual_sid = None
    if len(sys.argv) >= 2:
        manual_sid = int(sys.argv[1])
        print(f"Manual SteamID64 Key specified: {manual_sid}")
    else:
        print("No SteamID64 specified. Using [AUTO-DETECT] mode.")
        
    processed_count = 0
    for root, dirs, files in os.walk("."):
        if "BCK" in root or ".git" in root or "007-firstlight-toolkit" in root:
            continue
            
        has_index = "index.save" in files
        has_data = "data.save" in files
        
        if has_index or has_data:
            print(f"\nSave container folder: {root}")
            
            dec_sid = manual_sid
            if not dec_sid:
                if has_index:
                    detected = detect_source_steam_id(os.path.join(root, "index.save"))
                    if detected:
                        print(f"  [AUTO] Detected SteamID64 Key: {detected}")
                        dec_sid = detected
                    else:
                        print(f"  [WARN] Auto-detect failed. Falling back to default: {KNOWN_SOURCE_SID}")
                        dec_sid = KNOWN_SOURCE_SID
                else:
                    print(f"  [WARN] No index.save found. Falling back to default: {KNOWN_SOURCE_SID}")
                    dec_sid = KNOWN_SOURCE_SID

            if has_index:
                decrypt_index_file(os.path.join(root, "index.save"), dec_sid)
            if has_data:
                decrypt_data_file(os.path.join(root, "data.save"), dec_sid)
                
            processed_count += 1
            
    print("------------------------------------------------")
    print(f"Decryption completed. Processed {processed_count} save containers.")

if __name__ == "__main__":
    main()
