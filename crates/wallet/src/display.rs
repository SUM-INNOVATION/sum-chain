//! Display utilities for colored and formatted CLI output.

use colored::Colorize;

use crate::currency::{format_koppa, KOPPA_SYMBOL};

/// Print a success message
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg.green());
}

/// Print an error message
pub fn print_error(msg: &str) {
    println!("{} {}", "✗".red().bold(), msg.red());
}

/// Print a warning message
pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg.yellow());
}

/// Print an info message
pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

/// Print a header/title
pub fn print_header(title: &str) {
    println!("\n{}", title.bold().underline());
}

/// Print a labeled value
pub fn print_field(label: &str, value: &str) {
    println!("  {}: {}", label.dimmed(), value);
}

/// Print a labeled value (already colored)
#[allow(dead_code)]
pub fn print_field_colored(label: &str, value: &str, _color: Color) {
    // Value is already colored by caller
    println!("  {}: {}", label.dimmed(), value);
}

/// Color enum for display
#[allow(dead_code)]
pub enum Color {
    Green,
    Yellow,
    Red,
    Blue,
    Cyan,
    Magenta,
    White,
}

/// Print a Koppa balance
#[allow(dead_code)]
pub fn print_balance(balance: u128) {
    let formatted = format_koppa(balance);
    println!("{}", formatted.green().bold());
}

/// Print a Koppa amount with label
pub fn print_koppa_field(label: &str, amount: u128) {
    let formatted = format_koppa(amount);
    println!("  {}: {}", label.dimmed(), formatted.cyan());
}

/// Print transaction details in a nice format
pub fn print_transaction_summary(
    from: &str,
    to: &str,
    amount: u128,
    fee: u128,
    nonce: u64,
) {
    print_header("Transaction Summary");
    print_field("From", from);
    print_field("To", to);
    print_koppa_field("Amount", amount);
    print_koppa_field("Fee", fee);
    print_field("Nonce", &nonce.to_string());
    println!();
}

/// Print a confirmation prompt and return user's choice
pub fn confirm(message: &str) -> bool {
    use dialoguer::Confirm;

    Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()
        .unwrap_or(false)
}

/// Print a separator line
pub fn print_separator() {
    println!("{}", "─".repeat(50).dimmed());
}

/// Format an address with shortened display
pub fn format_address_short(address: &str) -> String {
    if address.len() > 16 {
        format!("{}...{}", &address[..8], &address[address.len() - 6..])
    } else {
        address.to_string()
    }
}

/// Print block info in a nice format
pub fn print_block_header(height: u64, hash: &str) {
    println!(
        "{} {} {}",
        "Block".bold(),
        format!("#{}", height).cyan().bold(),
        format!("({})", format_address_short(hash)).dimmed()
    );
}

/// Format timestamp to human readable
pub fn format_timestamp(unix_ms: u64) -> String {
    use chrono::DateTime;

    let secs = (unix_ms / 1000) as i64;
    let nsecs = ((unix_ms % 1000) * 1_000_000) as u32;

    if let Some(dt) = DateTime::from_timestamp(secs, nsecs) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        unix_ms.to_string()
    }
}

/// Print node status with colored indicators
pub fn print_status_indicator(label: &str, is_ok: bool) {
    let (icon, status) = if is_ok {
        ("●".green(), "Yes".green())
    } else {
        ("●".red(), "No".red())
    };
    println!("  {}: {} {}", label.dimmed(), icon, status);
}

/// Print a list item
pub fn print_list_item(index: usize, content: &str) {
    println!("  {} {}", format!("[{}]", index).dimmed(), content);
}

/// Print welcome banner for SUM Chain wallet
pub fn print_banner() {
    println!();
    println!("{}", "╭───────────────────────────────────────╮".cyan());
    println!("{}", "│         SUM Chain Wallet              │".cyan());
    println!(
        "{}",
        format!("│         Native Currency: {}           │", KOPPA_SYMBOL).cyan()
    );
    println!("{}", "╰───────────────────────────────────────╯".cyan());
    println!();
}
