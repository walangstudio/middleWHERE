//! Line-based terminal prompts shared by `init`, `wizard`, and the elevation
//! step. Deliberately no TUI dependency — plain stdin/stdout works on every
//! target (including the Rosetta cross-build that a full-screen TUI crate
//! breaks). Callers must have already ensured stdin is a terminal; EOF is an
//! error.

use std::io::{self, BufRead, Write};

use anyhow::{bail, Result};

/// Print a label and read one trimmed line. EOF (closed stdin) is an error —
/// the interactive flows require a real terminal (checked up front by callers).
pub(crate) fn read_line(label: &str) -> Result<String> {
    print!("{label} ");
    io::stdout().flush().ok();
    let mut s = String::new();
    if io::stdin().lock().read_line(&mut s)? == 0 {
        bail!("unexpected end of input");
    }
    Ok(s.trim().to_string())
}

/// Required free text; re-asks on a blank line.
pub(crate) fn prompt_text(label: &str) -> Result<String> {
    loop {
        let s = read_line(label)?;
        if !s.is_empty() {
            return Ok(s);
        }
        eprintln!("  ! required");
    }
}

/// Free text with a default applied on a blank line.
pub(crate) fn prompt_text_default(label: &str, default: &str) -> Result<String> {
    let s = read_line(&format!("{label} [{default}]:"))?;
    Ok(if s.is_empty() { default.to_string() } else { s })
}

/// Optional free text; a blank line means None.
pub(crate) fn prompt_optional_text(label: &str) -> Result<Option<String>> {
    let s = read_line(label)?;
    Ok(if s.is_empty() { None } else { Some(s) })
}

pub(crate) fn confirm(label: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        match read_line(&format!("{label} {hint}"))?
            .to_ascii_lowercase()
            .as_str()
        {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("  ! please answer y or n"),
        }
    }
}

/// Numbered single-select; returns the chosen 0-based index.
pub(crate) fn select_index(label: &str, labels: &[&str]) -> Result<usize> {
    println!("{label}");
    for (i, o) in labels.iter().enumerate() {
        println!("  {}) {o}", i + 1);
    }
    loop {
        let s = read_line("  choose [number]:")?;
        if let Ok(n) = s.parse::<usize>() {
            if (1..=labels.len()).contains(&n) {
                return Ok(n - 1);
            }
        }
        eprintln!("  ! enter a number 1-{}", labels.len());
    }
}

/// Numbered single-select over owned strings; returns the chosen value.
pub(crate) fn select_owned(label: &str, options: &[String]) -> Result<String> {
    let refs: Vec<&str> = options.iter().map(String::as_str).collect();
    Ok(options[select_index(label, &refs)?].clone())
}

/// Prompt for a port, re-asking on a non-numeric entry instead of aborting the
/// whole flow.
pub(crate) fn prompt_port(label: &str, default: u16) -> Result<u16> {
    loop {
        match prompt_text_default(label, &default.to_string())?.parse::<u16>() {
            Ok(p) => return Ok(p),
            Err(_) => eprintln!("  ! not a valid port (0-65535); try again"),
        }
    }
}

/// Like [`prompt_port`] but a blank line means "use the engine default" (None).
pub(crate) fn prompt_optional_port(label: &str) -> Result<Option<u16>> {
    loop {
        match prompt_optional_text(label)? {
            None => return Ok(None),
            Some(s) => match s.parse::<u16>() {
                Ok(p) => return Ok(Some(p)),
                Err(_) => eprintln!("  ! not a valid port (0-65535); try again"),
            },
        }
    }
}
