import os
import shutil
import struct
import sys
import zlib


def guess_xor_mask(index_path):
    if not os.path.exists(index_path):
        return None
    try:
        with open(index_path, "rb") as f:
            data = f.read()
        if len(data) < 24:
            return None
        pattern = b"meHeader"
        key_bytes = bytes(data[16 + i] ^ pattern[i] for i in range(8))
        key = struct.unpack("<Q", key_bytes)[0]
        
        decrypted = bytes(c ^ key_bytes[i % 8] for i, c in enumerate(data))
        if b"SSaveGameHeader" in decrypted:
            return key
    except Exception:
        pass
    return None


def detect_source_steam_id(index_path):
    guessed = guess_xor_mask(index_path)
    if guessed is not None:
        return guessed

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


def encrypt_data_file(decrypted_path, steam_sid):
    print("  Processing data.save.decrypted:")
    if not os.path.exists(decrypted_path):
        print(f"    [WARN] Decrypted save data not found: {decrypted_path}")
        return False
    with open(decrypted_path, 'rb') as f:
        decompressed_payload = f.read()
    compressed_payload = zlib.compress(decompressed_payload, level=4)
    sid_bytes = struct.pack("<Q", steam_sid)
    ciphertext = bytes(c ^ sid_bytes[i % 8] for i, c in enumerate(compressed_payload))
    dir_name = os.path.dirname(decrypted_path)
    output_path = os.path.join(dir_name, "data.save")
    if os.path.exists(output_path):
        backup_path = output_path + ".backup"
        if not os.path.exists(backup_path):
            shutil.copy2(output_path, backup_path)
            print(f"    [OK] Existing data.save backed up -> {os.path.basename(backup_path)}")
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    print(f"    [SUCCESS] Encrypted and packed save saved to -> {os.path.basename(output_path)}\n")
    return True


def encrypt_index_file(decrypted_path, steam_sid):
    print("  Processing index.save.decrypted:")
    if not os.path.exists(decrypted_path):
        print(f"    [WARN] Decrypted index file not found: {decrypted_path}")
        return False
    with open(decrypted_path, 'rb') as f:
        data = f.read()
    if len(data) < 8:
        print("    [ERROR] index file is too short.")
        return False
    sid_bytes = struct.pack("<Q", steam_sid)
    ciphertext = bytes(c ^ sid_bytes[i % 8] for i, c in enumerate(data))
    dir_name = os.path.dirname(decrypted_path)
    output_path = os.path.join(dir_name, "index.save")
    if os.path.exists(output_path):
        backup_path = output_path + ".backup"
        if not os.path.exists(backup_path):
            shutil.copy2(output_path, backup_path)
            print(f"    [OK] Existing index.save backed up -> {os.path.basename(backup_path)}")
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    print(f"    [SUCCESS] Encrypted index saved to -> {os.path.basename(output_path)}\n")
    return True


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    print("007 First Light (Knight) Save Encrypter & Packer")
    print("===============================================")
    sys.stdout.write("Enter save container directory (default: current directory): ")
    sys.stdout.flush()
    target_dir = input().strip()
    if not target_dir:
        target_dir = "."
    if not os.path.isdir(target_dir):
        print(f"[ERROR] Directory not found: {target_dir}")
        sys.exit(1)
    decrypted_data_path = os.path.join(target_dir, "data.save.decrypted")
    decrypted_index_path = os.path.join(target_dir, "index.save.decrypted")
    has_data_dec = os.path.exists(decrypted_data_path)
    has_index_dec = os.path.exists(decrypted_index_path)
    if not has_data_dec and not has_index_dec:
        print("[ERROR] No decrypted save files (.decrypted) found in this directory.")
        sys.exit(1)
    target_sid = None
    sys.stdout.write("Enter target SteamID64 key for encryption (Press Enter to auto-detect): ")
    sys.stdout.flush()
    sid_input = input().strip()
    if sid_input:
        target_sid = int(sid_input)
    else:
        index_file = os.path.join(target_dir, "index.save")
        if os.path.exists(index_file):
            target_sid = detect_source_steam_id(index_file)
            if target_sid:
                print(f"  [AUTO] Auto-detected Target SteamID64 from index: {target_sid}")
            else:
                print("  [WARN] Auto-detect failed. Proceeding without data.save encryption.")
        else:
            print("  [WARN] index.save not found. Proceeding without data.save encryption.")
    print("\nStarting Save Encryption & Packing...")
    print("------------------------------------------------")
    if has_index_dec:
        if target_sid:
            encrypt_index_file(decrypted_index_path, target_sid)
        else:
            print("  [SKIP] Skipping index.save encryption because no SteamID64 key was specified or detected.")
    if has_data_dec:
        if target_sid:
            encrypt_data_file(decrypted_data_path, target_sid)
        else:
            print("  [SKIP] Skipping data.save encryption because no SteamID64 key was specified or detected.")
    print("------------------------------------------------")
    print("Encryption and packing completed.")

if __name__ == "__main__":
    main()
