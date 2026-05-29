use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::hex_bytes;
use crate::crypto::{resolve_steam_id, xor_with_key, zlib_decompress};

const KNOWN_VARS: &[&str] = &[
    "Spawnpoint",
    "Version",
    "Timestamp",
    "Difficulty",
    "Finished",
    "HasSessionData",
    "Agency",
    "Outfit",
    "Guid",
    "Firearms",
    "Value",
    "State",
    "DynamicallySpawned",
    "PlayerAmmunition",
    "Resources",
];

/// A parsed save record.
struct Record {
    offset:   usize,
    variable: &'static str,
    datatype: String,
    value:    String,
}

pub fn cmd_parse_file(path: &Path, steam_id: Option<u64>) {
    println!("007 First Light (Knight) Save Parser");
    println!("====================================");

    let raw = fs::read(path).expect("cannot read file");
    let data: Vec<u8> = if raw.starts_with(&[0x03, 0x00, 0x00, 0x00]) {
        println!("  [INFO] File appears to be already decrypted.");
        raw
    } else {
        println!("  [INFO] File is encrypted. Attempting to decrypt...");
        let dir        = path.parent().unwrap_or(Path::new("."));
        let index_path = dir.join("index.save");
        let sid = resolve_steam_id(steam_id, &index_path, Some(path), true)
            .unwrap_or_else(|| {
                eprintln!(
                    "  [ERROR] Cannot determine SteamID. Use --steam-id or ensure index.save is present."
                );
                std::process::exit(1);
            });
        let xored = xor_with_key(&raw, sid);
        zlib_decompress(&xored).unwrap_or_else(|| {
            eprintln!("  [ERROR] Decompression failed. Decryption SteamID may be incorrect.");
            std::process::exit(1);
        })
    };

    println!("  [OK] Successfully loaded save payload ({} raw decompressed bytes).", data.len());
    println!("\nParsing Glacier Next serialized records...");
    println!("{}", "=".repeat(100));
    println!(
        "{:<8} | {:<25} | {:<25} | {:<35}",
        "Offset", "Variable Name", "Type / Context", "Value (Hex / Decoded)"
    );
    println!("{}", "=".repeat(100));

    let mut records: Vec<Record> = Vec::new();
    let mut offset = 0usize;

    while offset + 8 < data.len() {
        if let Some((str_val, next_offset)) = read_serialized_string(&data, offset) {
            if str_val.len() > 2 {
                let val_offset = next_offset;
                if let Some(&var) = KNOWN_VARS.iter().find(|&&v| v == str_val.as_str()) {
                    let context = &data[val_offset..data.len().min(val_offset + 16)];
                    let (datatype, value) = parse_known_var(var, &data, val_offset, context);
                    println!("0x{offset:04X}   | {var:<25} | {datatype:<25} | {value:<35}");
                    records.push(Record { offset, variable: var, datatype, value });
                }
                offset = next_offset;
            } else {
                offset += 1;
            }
        } else {
            offset += 1;
        }
    }

    println!("{}", "=".repeat(100));
    println!("Successfully identified and parsed {} key records.", records.len());

    write_txt_report(path, &data, &records);
    write_json_map(path, &records);
}

fn write_txt_report(source: &Path, data: &[u8], records: &[Record]) {
    let base = PathBuf::from(source.with_extension("").to_string_lossy().as_ref());
    let path = PathBuf::from(format!("{}_report.txt", base.display()));
    let mut out = String::new();
    out.push_str("007 First Light (Knight) Save File Parsed Data\n");
    out.push_str("================================================\n");
    out.push_str(&format!("Source Save File:   {}\n", source.display()));
    out.push_str(&format!("Decompressed Size:  {} bytes\n", data.len()));
    out.push_str(&format!(
        "Generated At:       {}\n\n",
        chrono_now_or_placeholder()
    ));
    out.push_str(&format!(
        "{:<8} | {:<25} | {:<25} | {:<35}\n",
        "Offset", "Variable Name", "Datatype / Schema", "Decoded Value"
    ));
    out.push_str(&"-".repeat(100));
    out.push('\n');
    for rec in records {
        out.push_str(&format!(
            "{:<8} | {:<25} | {:<25} | {:<35}\n",
            format!("0x{:04X}", rec.offset),
            rec.variable,
            rec.datatype,
            rec.value,
        ));
    }
    out.push_str(&"-".repeat(100));
    out.push('\n');
    out.push_str(&format!(
        "Parsed {} structured save records successfully.\n",
        records.len()
    ));
    fs::write(&path, &out).expect("cannot write txt report");
    println!(
        "\n  [SUCCESS] Text report saved to: {}",
        path.file_name().unwrap().to_string_lossy()
    );
}

fn write_json_map(source: &Path, records: &[Record]) {
    let base = PathBuf::from(source.with_extension("").to_string_lossy().as_ref());
    let path = PathBuf::from(format!("{}_variables.json", base.display()));
    let mut json = String::from("{\n");
    for (i, rec) in records.iter().enumerate() {
        let comma = if i + 1 < records.len() { "," } else { "" };
        let val_json = json_escape(&rec.value);
        json.push_str(&format!(
            "  \"{}\": {{\n    \"offset\": \"0x{:04X}\",\n    \"offset_int\": {},\n    \"datatype\": \"{}\",\n    \"value\": {}\n  }}{}\n",
            rec.variable,
            rec.offset,
            rec.offset,
            rec.datatype,
            val_json,
            comma,
        ));
    }
    json.push('}');
    fs::write(&path, &json).expect("cannot write json map");
    println!(
        "  [SUCCESS] JSON variables map saved to: {}",
        path.file_name().unwrap().to_string_lossy()
    );
}

fn json_escape(s: &str) -> String {
    if s.parse::<f64>().is_ok() || s.parse::<i64>().is_ok() {
        return s.to_string();
    }
    if s.is_empty() {
        return "null".to_string();
    }
    if s == "true"  { return "true".to_string();  }
    if s == "false" { return "false".to_string(); }
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
    format!("\"{escaped}\"")
}

fn chrono_now_or_placeholder() -> String {
    "see file modification time".to_string()
}

fn parse_known_var(var: &str, data: &[u8], val_offset: usize, context: &[u8]) -> (String, String) {
    match var {
        "Version" => {
            match read_serialized_string(data, val_offset + 5) {
                Some((s, _)) => ("ZString".into(), format!("'{s}'")),
                None          => ("ZString".into(), String::new()),
            }
        }
        "Spawnpoint" => {
            match read_serialized_string(data, val_offset + 13) {
                Some((s, _)) => ("ZString".into(), format!("'{s}'")),
                None          => ("ZString".into(), String::new()),
            }
        }
        "Difficulty" | "Value" | "State" | "Agency" => {
            if context.len() >= 8 {
                let v = f64::from_le_bytes(context[..8].try_into().unwrap());
                ("float64 (double)".into(), format!("{v}"))
            } else {
                ("float64 (double)".into(), String::new())
            }
        }
        "Timestamp" => {
            if val_offset + 21 <= data.len() {
                let v = f64::from_le_bytes(
                    data[val_offset + 13..val_offset + 21].try_into().unwrap(),
                );
                ("float64 (double)".into(), format!("{v} (Unix epoch)"))
            } else {
                ("float64 (double)".into(), String::new())
            }
        }
        "Finished" => {
            if val_offset + 10 < data.len() {
                let v = data[val_offset + 10] != 0;
                ("bool".into(), format!("{v}"))
            } else {
                ("bool".into(), String::new())
            }
        }
        "HasSessionData" => {
            if val_offset + 1 < data.len() {
                let v = data[val_offset + 1] != 0;
                ("bool".into(), format!("{v}"))
            } else {
                ("bool".into(), String::new())
            }
        }
        "DynamicallySpawned" => {
            if val_offset < data.len() {
                let v = data[val_offset] != 0;
                ("bool".into(), format!("{v}"))
            } else {
                ("bool".into(), String::new())
            }
        }
        "Guid" => {
            match read_serialized_string(data, val_offset + 4) {
                Some((s, _)) => ("ZString".into(), format!("'{s}'")),
                None          => ("ZString".into(), String::new()),
            }
        }
        _ => {
            let n = 8.min(context.len());
            ("Container/Array".into(), format!("Header: {}", hex_bytes(&context[..n])))
        }
    }
}

pub fn read_serialized_string(data: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset + 4 > data.len() {
        return None;
    }
    let length_int = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    let is_string  = (length_int & 0x8000_0000) != 0;
    let length     = (length_int & 0x7FFF_FFFF) as usize;

    if is_string && length < 256 && offset + 4 + length <= data.len() {
        let s = String::from_utf8_lossy(&data[offset + 4..offset + 4 + length]).into_owned();
        Some((s, offset + 4 + length))
    } else {
        None
    }
}