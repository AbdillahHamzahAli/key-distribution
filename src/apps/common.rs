//! Interactive input helpers shared by the KDC and the peers.

use std::io::{self, Write};

use crate::crypto::codec::Key;
use crate::protocol::messages::Id;

/// Print a prompt and read one trimmed line. Returns `None` on EOF.
pub fn read_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();

    let mut buffer = String::new();
    match io::stdin().read_line(&mut buffer) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(buffer.trim().to_string()),
    }
}

pub fn prompt_text(label: &str, default: Option<&str>) -> Option<String> {
    loop {
        let suffix = match default {
            Some(value) => format!(" (default {value}): "),
            None => ": ".to_string(),
        };
        match read_line(&format!("{label}{suffix}")) {
            None => return None,
            Some(value) if !value.is_empty() => return Some(value),
            Some(_) => {
                if let Some(value) = default {
                    return Some(value.to_string());
                }
            }
        }
    }
}

pub fn prompt_port(label: &str, default: Option<u16>) -> Option<u16> {
    loop {
        let suffix = match default {
            Some(value) => format!(" (default {value}): "),
            None => ": ".to_string(),
        };
        let raw = read_line(&format!("{label}{suffix}"))?;
        if raw.is_empty()
            && let Some(value) = default
        {
            return Some(value);
        }
        match raw.parse::<u16>() {
            Ok(port) if port != 0 => return Some(port),
            _ => println!("-> must be an integer 1..65535"),
        }
    }
}

pub fn prompt_id(label: &str) -> Option<Id> {
    loop {
        let value = read_line(&format!("{label}: "))?;
        match Id::new(&value) {
            Ok(id) => return Some(id),
            Err(error) => println!("-> {error}"),
        }
    }
}

pub fn prompt_key(label: &str) -> Option<Key> {
    loop {
        let value = read_line(&format!("{label} (exactly 16 ASCII chars): "))?;
        match Key::new(&value) {
            Ok(key) => return Some(key),
            Err(error) => println!("-> {error}"),
        }
    }
}
