import json
import os
import struct
import sys
import time
import zlib

KNOWN_SOURCE_SID = 76561198026925824

def detect_source_steam_id(index_path):
    target_path = index_path + ".backup"
    if not os.path.exists(target_path):
        target_path = index_path
        
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


def bruteforce_data_save_key(ciphertext):
    if len(ciphertext) < 32:
        return None
        
    b0 = ciphertext[0] ^ 0x78
    valid_flgs = [0x01, 0x5E, 0x9C, 0xDA]
    b1_candidates = [ciphertext[1] ^ flg for flg in valid_flgs]
    header_chunk = ciphertext[:16]
    
    for b1 in b1_candidates:
        for b2 in range(256):
            for b3 in range(256):
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
                        zlib.decompress(full_decrypted)
                        
                        steam_id = struct.unpack("<Q", key)[0]
                        return steam_id
                    except Exception:
                        pass
    return None


def get_decompressed_payload(filepath):
    with open(filepath, "rb") as f:
        ciphertext = f.read()
        
    if len(ciphertext) < 8:
        print("[ERROR] File is too small.")
        return None
        
    if ciphertext.startswith(b"\x03\x00\x00\x00"):
        return ciphertext
        
    print("  [INFO] File is encrypted. Attempting to decrypt...")
    
    dir_name = os.path.dirname(filepath)
    index_path = os.path.join(dir_name, "index.save")
    
    steam_id = None
    if os.path.exists(index_path):
        detected_sid = detect_source_steam_id(index_path)
        if detected_sid:
            print(f"  [AUTO] Detected SteamID64 from index.save: {detected_sid}")
            sid_bytes = struct.pack("<Q", detected_sid)
            decrypted_xor = bytes(c ^ sid_bytes[i % 8] for i, c in enumerate(ciphertext))
            try:
                zlib.decompress(decrypted_xor)
                steam_id = detected_sid
            except Exception:
                print("  [WARN] Index SteamID decryption failed. Falling back to brute-force.")
                
    if not steam_id:
        print("  [AUTO] Running accelerated brute-forcer to crack SteamID key...")
        start_t = time.time()
        cracked = bruteforce_data_save_key(ciphertext)
        elapsed = time.time() - start_t
        if cracked:
            print(f"  [SUCCESS] Standalone cracked SteamID64 Key in {elapsed:.3f}s: {cracked}")
            steam_id = cracked
        else:
            print("  [WARN] Standalone brute-forcer failed. Falling back to default.")
            steam_id = KNOWN_SOURCE_SID
            
    sid_bytes = struct.pack("<Q", steam_id)
    decrypted_xor = bytes(c ^ sid_bytes[i % 8] for i, c in enumerate(ciphertext))
    try:
        decompressed = zlib.decompress(decrypted_xor)
        return decompressed
    except Exception as e:
        print(f"  [ERROR] Decompression failed. Decryption SteamID may be incorrect: {e}")
        return None


def read_serialized_string(data, offset):
    if offset + 4 > len(data):
        return None, offset
    length_int = struct.unpack_from("<I", data, offset)[0]
    is_string = (length_int & 0x80000000) != 0
    length = length_int & 0x7FFFFFFF
    
    if is_string and length < 256 and offset + 4 + length <= len(data):
        try:
            val = data[offset+4:offset+4+length].decode('utf-8', errors='replace')
            return val, offset + 4 + length
        except Exception:
            pass
    return None, offset


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
        
    print("007 First Light (Knight) Save Parser")
    print("====================================")
    
    filepath = ""
    if len(sys.argv) >= 2:
        filepath = sys.argv[1]
    else:
        sys.stdout.write("Enter path to save file (default: data.save): ")
        sys.stdout.flush()
        filepath = input().strip()
        if not filepath:
            filepath = "data.save"
            
    if not os.path.exists(filepath):
        print(f"[ERROR] Save file not found: {filepath}")
        sys.exit(1)
        
    data = get_decompressed_payload(filepath)
    if not data:
        sys.exit(1)
        
    print(f"  [OK] Successfully loaded save payload ({len(data)} raw decompressed bytes).")
    
    print("\nParsing Glacier Next serialized records...")
    print("=" * 100)
    print(f"{'Offset':<8} | {'Variable Name':<25} | {'Type / Context':<25} | {'Value (Hex / Decoded)':<35}")
    print("=" * 100)
    
    offset = 0
    found_records = []
    
    while offset < len(data) - 8:
        str_val, next_offset = read_serialized_string(data, offset)
        if str_val and len(str_val) > 2:
            val_offset = next_offset
            context = data[val_offset:val_offset+16]
            
            known_vars = [
                "Spawnpoint", "Version", "Timestamp", "Difficulty", "Finished", 
                "HasSessionData", "Agency", "Outfit", "Guid", "Firearms", "Value", 
                "State", "DynamicallySpawned", "PlayerAmmunition", "Resources"
            ]
            
            if str_val in known_vars:
                decoded_val = ""
                datatype = "Unknown"
                raw_val = None
                
                if str_val == "Version":
                    datatype = "ZString"
                    str_val_inner, _ = read_serialized_string(data, val_offset + 5)
                    decoded_val = f"'{str_val_inner}'" if str_val_inner else ""
                    raw_val = str_val_inner
                elif str_val == "Spawnpoint":
                    datatype = "ZString"
                    str_val_inner, _ = read_serialized_string(data, val_offset + 13)
                    decoded_val = f"'{str_val_inner}'" if str_val_inner else ""
                    raw_val = str_val_inner
                elif str_val == "Difficulty":
                    datatype = "float64 (double)"
                    if len(context) >= 8:
                        val = struct.unpack("<d", context[:8])[0]
                        decoded_val = f"{val}"
                        raw_val = val
                elif str_val == "Timestamp":
                    datatype = "float64 (double)"
                    t_bytes = data[val_offset+13:val_offset+21]
                    if len(t_bytes) == 8:
                        val = struct.unpack("<d", t_bytes)[0]
                        decoded_val = f"{val} (Unix epoch)"
                        raw_val = val
                elif str_val == "Finished":
                    datatype = "bool"
                    if val_offset + 10 < len(data):
                        val = data[val_offset+10] != 0
                        decoded_val = f"{val}"
                        raw_val = val
                elif str_val == "HasSessionData":
                    datatype = "bool"
                    if val_offset + 1 < len(data):
                        val = data[val_offset+1] != 0
                        decoded_val = f"{val}"
                        raw_val = val
                elif str_val == "Agency":
                    datatype = "float64 (double)"
                    if val_offset + 8 <= len(data):
                        val = struct.unpack("<d", data[val_offset:val_offset+8])[0]
                        decoded_val = f"{val}"
                        raw_val = val
                elif str_val == "Guid":
                    datatype = "ZString"
                    str_val_inner, _ = read_serialized_string(data, val_offset + 4)
                    decoded_val = f"'{str_val_inner}'" if str_val_inner else ""
                    raw_val = str_val_inner
                elif str_val == "Value":
                    datatype = "float64 (double)"
                    if len(context) >= 8:
                        val = struct.unpack("<d", context[:8])[0]
                        decoded_val = f"{val}"
                        raw_val = val
                elif str_val == "State":
                    datatype = "float64 (double)"
                    if len(context) >= 8:
                        val = struct.unpack("<d", context[:8])[0]
                        decoded_val = f"{val}"
                        raw_val = val
                elif str_val == "DynamicallySpawned":
                    datatype = "bool"
                    if val_offset < len(data):
                        val = data[val_offset] != 0
                        decoded_val = f"{val}"
                        raw_val = val
                else:
                    datatype = "Container/Array"
                    decoded_val = f"Header: {context[:8].hex(' ')}"
                    raw_val = context[:8].hex(' ')
                    
                print(f"0x{offset:04X}   | {str_val:<25} | {datatype:<25} | {decoded_val:<35}")
                found_records.append({
                    "offset": f"0x{offset:04X}",
                    "offset_int": offset,
                    "variable": str_val,
                    "datatype": datatype,
                    "value": decoded_val,
                    "raw_value": raw_val
                })
                
            offset = next_offset
        else:
            offset += 1
            
    print("=" * 100)
    print(f"Successfully identified and parsed {len(found_records)} key records.")
    
    base_name = os.path.splitext(filepath)[0]
    txt_report_path = f"{base_name}_report.txt"
    json_map_path = f"{base_name}_variables.json"
    
    with open(txt_report_path, "w", encoding="utf-8") as rf:
        rf.write("007 First Light (Knight) Save File Parsed Data\n")
        rf.write("================================================\n")
        rf.write(f"Source Save File:   {filepath}\n")
        rf.write(f"Decompressed Size:  {len(data)} bytes\n")
        rf.write(f"Generated At:       {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        rf.write(f"{'Offset':<8} | {'Variable Name':<25} | {'Datatype / Schema':<25} | {'Decoded Value':<35}\n")
        rf.write("-" * 100 + "\n")
        for rec in found_records:
            rf.write(f"{rec['offset']:<8} | {rec['variable']:<25} | {rec['datatype']:<25} | {rec['value']:<35}\n")
        rf.write("-" * 100 + "\n")
        rf.write(f"Parsed {len(found_records)} structured save records successfully.\n")
        
    print(f"\n  [SUCCESS] Text report saved to: {os.path.basename(txt_report_path)}")
    
    json_vars = {rec["variable"]: {
        "offset": rec["offset"],
        "offset_int": rec["offset_int"],
        "datatype": rec["datatype"],
        "value": rec["raw_value"]
    } for rec in found_records}
    
    with open(json_map_path, "w", encoding="utf-8") as jf:
        json.dump(json_vars, jf, indent=2)
        
    print(f"  [SUCCESS] JSON variables map saved to: {os.path.basename(json_map_path)}")

if __name__ == "__main__":
    main()
