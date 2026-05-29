use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

pub const STEAM_BASE: u64 = 76_561_197_960_265_728;
pub const VALID_FLG: [u8; 4] = [0x01, 0x5E, 0x9C, 0xDA];
pub const STEAM_ID_UPPER_LE: [u8; 4] = [0x01, 0x00, 0x10, 0x01];

pub fn xor_with_key(data: &[u8], key: u64) -> Vec<u8> {
    let key_bytes = key.to_le_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % 8])
        .collect()
}

pub fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok()?;
    Some(out)
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(4));
    enc.write_all(data).expect("zlib write failed");
    enc.finish().expect("zlib finish failed")
}

pub fn detect_steam_id_from_index(raw: &[u8]) -> Option<u64> {
    if raw.len() < 28 {
        return None;
    }
    let account_id = u32::from_le_bytes(raw[24..28].try_into().ok()?);
    Some(STEAM_BASE + account_id as u64)
}

pub fn detect_steam_id_from_index_path(index_path: &Path) -> Option<u64> {
    let ext = index_path.extension().unwrap_or_default().to_string_lossy();
    let bak = index_path.with_extension(format!("{ext}.backup"));
    let target = if bak.exists() { bak } else { index_path.to_path_buf() };
    let raw = fs::read(&target).ok()?;
    detect_steam_id_from_index(&raw)
}

pub fn crack_index_save(ciphertext: &[u8]) -> Option<u64> {
    if ciphertext.len() < 8 {
        return None;
    }
    let key: [u8; 8] = [
        ciphertext[0] ^ 0x03,
        ciphertext[1] ^ 0x00,
        ciphertext[2] ^ 0x00,
        ciphertext[3] ^ 0x00,
        STEAM_ID_UPPER_LE[0],
        STEAM_ID_UPPER_LE[1],
        STEAM_ID_UPPER_LE[2],
        STEAM_ID_UPPER_LE[3],
    ];
    let key_u64 = u64::from_le_bytes(key);
    let decrypted = xor_with_key(ciphertext, key_u64);
    if decrypted.windows(15).any(|w| w == b"SSaveGameHeader") {
        Some(key_u64)
    } else {
        None
    }
}

pub fn bruteforce_data_save(ciphertext: &[u8]) -> Option<u64> {
    if ciphertext.len() < 32 {
        return None;
    }
    let b0 = ciphertext[0] ^ 0x78;
    let header_chunk = &ciphertext[..16];

    for &flg in &VALID_FLG {
        let b1 = ciphertext[1] ^ flg;
        for b2 in 0u8..=255 {
            for b3 in 0u8..=255 {
                let key_bytes = [
                    b0, b1, b2, b3,
                    STEAM_ID_UPPER_LE[0],
                    STEAM_ID_UPPER_LE[1],
                    STEAM_ID_UPPER_LE[2],
                    STEAM_ID_UPPER_LE[3],
                ];
                let key = u64::from_le_bytes(key_bytes);
                let cmf     = header_chunk[0] ^ key_bytes[0];
                let flg_dec = header_chunk[1] ^ key_bytes[1];
                if cmf != 0x78 || ((cmf as u32) * 256 + flg_dec as u32) % 31 != 0 {
                    continue;
                }

                let dec = xor_with_key(ciphertext, key);
                if zlib_decompress(&dec).is_some() {
                    return Some(key);
                }
            }
        }
    }
    None
}

pub fn resolve_steam_id(
    explicit: Option<u64>,
    index_path: &Path,
    data_path: Option<&Path>,
    do_bruteforce: bool,
) -> Option<u64> {
    if let Some(sid) = explicit {
        return Some(sid);
    }
    if index_path.exists() {
        if let Some(sid) = detect_steam_id_from_index_path(index_path) {
            println!("  [AUTO] Detected SteamID64 from index.save: {sid}");
            return Some(sid);
        }
    }
    if do_bruteforce {
        if let Some(dp) = data_path {
            if dp.exists() {
                print!("  [AUTO] Brute-forcing... ");
                std::io::stdout().flush().ok();
                let start = Instant::now();
                let ct = fs::read(dp).ok()?;
                match bruteforce_data_save(&ct) {
                    Some(key) => {
                        println!("cracked in {:.3?}: {key}", start.elapsed());
                        return Some(key);
                    }
                    None => println!("FAILED"),
                }
            }
        }
    }
    None
}