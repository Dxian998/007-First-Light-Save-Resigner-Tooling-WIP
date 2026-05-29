mod cli;
mod crypto;
mod utils;
mod ops;
mod parser;

use std::path::{Path, PathBuf};

use cli::{arg, parse_u64, require_arg};
use ops::{
    cmd_bruteforce_file, cmd_bruteforce_folder,
    cmd_decrypt_file, cmd_decrypt_folder,
    cmd_encrypt_file, cmd_encrypt_folder,
    cmd_resign_file, cmd_resign_folder,
};
use parser::cmd_parse_file;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "007 First Light (Knight) Save Tool\n\
             ==================================\n\
             \n\
             Usage:\n\
             \n  {0} decrypt    --file <path> | --folder <path>  [--steam-id <SteamID64>]\
             \n  {0} encrypt    --file <path> | --folder <path>  [--steam-id <SteamID64>]\
             \n  {0} resign     --file <path> | --folder <path>  --to-id <SteamID64>  [--from-id <SteamID64>]  [-y]\
             \n  {0} bruteforce --file <path> | --folder <path>\
             \n  {0} parse      --file <path>                    [--steam-id <SteamID64>]\
             \n\
             \nNotes:\
             \n  decrypt / encrypt operate on index.save / data.save (or their .decrypted variants)\
             \n  --folder walks subdirectories for save containers automatically\
             \n  SteamID64 is auto-detected from index.save when omitted\
             \n  All numeric values accept decimal or 0x-prefixed hex\
             \n  -y / --yes skips interactive confirmation prompts",
            args[0]
        );
        std::process::exit(1);
    }

    let auto_confirm = args.iter().any(|a| a == "-y" || a == "--yes");

    match args[1].as_str() {
        "decrypt" => {
            let steam_id = arg(&args, "--steam-id").map(|s| parse_u64(&s));
            if let Some(folder) = arg(&args, "--folder") {
                cmd_decrypt_folder(Path::new(&folder), steam_id);
            } else {
                cmd_decrypt_file(&PathBuf::from(require_arg(&args, "--file")), steam_id);
            }
        }

        "encrypt" => {
            let steam_id = arg(&args, "--steam-id").map(|s| parse_u64(&s));
            if let Some(folder) = arg(&args, "--folder") {
                cmd_encrypt_folder(Path::new(&folder), steam_id);
            } else {
                cmd_encrypt_file(&PathBuf::from(require_arg(&args, "--file")), steam_id);
            }
        }

        "resign" => {
            let to_id   = parse_u64(&require_arg(&args, "--to-id"));
            let from_id = arg(&args, "--from-id").map(|s| parse_u64(&s));
            if let Some(folder) = arg(&args, "--folder") {
                cmd_resign_folder(Path::new(&folder), to_id, from_id, auto_confirm);
            } else {
                cmd_resign_file(&PathBuf::from(require_arg(&args, "--file")), to_id, from_id);
            }
        }

        "bruteforce" => {
            if let Some(folder) = arg(&args, "--folder") {
                cmd_bruteforce_folder(Path::new(&folder));
            } else {
                cmd_bruteforce_file(&PathBuf::from(require_arg(&args, "--file")));
            }
        }

        "parse" => {
            let file     = PathBuf::from(require_arg(&args, "--file"));
            let steam_id = arg(&args, "--steam-id").map(|s| parse_u64(&s));
            cmd_parse_file(&file, steam_id);
        }

        other => {
            eprintln!("[ERROR] unknown command: '{other}'");
            eprintln!("        Run without arguments to see usage.");
            std::process::exit(1);
        }
    }
}