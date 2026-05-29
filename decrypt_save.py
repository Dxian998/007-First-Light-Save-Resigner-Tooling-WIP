import os
import struct
import sys
import zlib

KNOWN_SOURCE_SID = 76561198026925824
INDEX_XOR_KEY = bytes.fromhex("cb 1c c4 0c 20 2e 20 2d 38 1b fa 27 28 29 19 2b 2d 0e 86 38 20 22 3c 35")

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


def decrypt_index_file(filepath):
    print(f"  Processing index.save:")
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
        
    if len(data) < 28:
        print("    [ERROR] index.save file is too short.")
        return
        
    acc_0 = struct.unpack_from("<I", data, 0)[0]
    acc_18 = struct.unpack_from("<I", data, 24)[0]
    
    print(f"    Header AccountID signature (offset 0x00): {acc_0 - 3} (raw: {acc_0})")
    print(f"    Main AccountID signature   (offset 0x18): {acc_18}")

    if len(data) > 0x148:
        length = data[0x145]
        str_bytes = data[0x148:0x148+length]
        
        dec_chars = []
        for i, b in enumerate(str_bytes):
            dec_chars.append(b ^ INDEX_XOR_KEY[i % len(INDEX_XOR_KEY)])
        dec_str_bytes = bytes(dec_chars)
        
        try:
            dec_str = dec_str_bytes.decode('utf-8', errors='replace')
        except Exception:
            dec_str = dec_str_bytes.hex(' ')
            
        print(f"    Decrypted internal path record (offset 0x148): '{dec_str}'")
        
        data[0x148:0x148+length] = dec_str_bytes
        
    out_path = filepath + ".decrypted"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"    [SUCCESS] Dumped decrypted index metadata in-place -> {os.path.basename(out_path)}\n")


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
                decrypt_index_file(os.path.join(root, "index.save"))
            if has_data:
                decrypt_data_file(os.path.join(root, "data.save"), dec_sid)
                
            processed_count += 1
            
    print("------------------------------------------------")
    print(f"Decryption completed. Processed {processed_count} save containers.")

if __name__ == "__main__":
    main()
