use std::io::Write;

pub fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
}

pub fn require_arg(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("[ERROR] missing required argument: {name}");
        std::process::exit(1);
    })
}

pub fn parse_u64(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or_else(|_| {
            eprintln!("[ERROR] invalid hex u64: {s}");
            std::process::exit(1);
        })
    } else {
        s.parse::<u64>().unwrap_or_else(|_| {
            eprintln!("[ERROR] invalid u64: {s}");
            std::process::exit(1);
        })
    }
}

pub fn confirm(prompt: &str, default: bool) -> bool {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    print!("  {prompt} {suffix}: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    let trimmed = line.trim().to_lowercase();
    if trimmed.is_empty() {
        return default;
    }
    matches!(trimmed.as_str(), "y" | "yes")
}

pub fn hex_bytes(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}