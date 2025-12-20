//! Koppa (Ϙ) currency formatting and display utilities.
//!
//! The native currency of SUM Chain is Koppa, represented by the symbol Ϙ.
//! Koppa has 9 decimal places (1 Koppa = 1,000,000,000 base units).

use std::fmt;

/// Number of decimal places in Koppa
pub const KOPPA_DECIMALS: u32 = 9;

/// One Koppa in base units
pub const KOPPA_UNIT: u128 = 1_000_000_000;

/// Koppa currency symbol (Greek letter Koppa)
pub const KOPPA_SYMBOL: &str = "Ϙ";

/// Koppa currency name
pub const KOPPA_NAME: &str = "Koppa";

/// Format a balance in base units as a human-readable Koppa amount.
///
/// # Examples
/// ```
/// use sumchain_wallet::currency::format_koppa;
///
/// assert_eq!(format_koppa(1_500_000_000), "1.5 Ϙ");
/// assert_eq!(format_koppa(100_000_000), "0.1 Ϙ");
/// assert_eq!(format_koppa(1_000_000_000_000), "1,000 Ϙ");
/// ```
pub fn format_koppa(base_units: u128) -> String {
    let whole = base_units / KOPPA_UNIT;
    let fraction = base_units % KOPPA_UNIT;

    if fraction == 0 {
        format!("{} {}", format_with_commas(whole), KOPPA_SYMBOL)
    } else {
        // Remove trailing zeros from fraction
        let fraction_str = format!("{:09}", fraction);
        let trimmed = fraction_str.trim_end_matches('0');
        format!("{}.{} {}", format_with_commas(whole), trimmed, KOPPA_SYMBOL)
    }
}

/// Format a balance with full currency name.
///
/// # Examples
/// ```
/// use sumchain_wallet::currency::format_koppa_full;
///
/// assert_eq!(format_koppa_full(1_500_000_000), "1.5 Koppa (Ϙ)");
/// ```
#[allow(dead_code)]
pub fn format_koppa_full(base_units: u128) -> String {
    let whole = base_units / KOPPA_UNIT;
    let fraction = base_units % KOPPA_UNIT;

    if fraction == 0 {
        format!("{} {} ({})", format_with_commas(whole), KOPPA_NAME, KOPPA_SYMBOL)
    } else {
        let fraction_str = format!("{:09}", fraction);
        let trimmed = fraction_str.trim_end_matches('0');
        format!(
            "{}.{} {} ({})",
            format_with_commas(whole),
            trimmed,
            KOPPA_NAME,
            KOPPA_SYMBOL
        )
    }
}

/// Parse a Koppa amount string into base units.
///
/// Accepts formats like:
/// - "1.5" -> 1_500_000_000
/// - "1" -> 1_000_000_000
/// - "0.001" -> 1_000_000
///
/// # Errors
/// Returns an error if the string cannot be parsed as a valid Koppa amount.
pub fn parse_koppa(amount: &str) -> Result<u128, ParseKoppaError> {
    // Remove any Koppa symbols or names
    let cleaned = amount
        .trim()
        .replace(KOPPA_SYMBOL, "")
        .replace(KOPPA_NAME, "")
        .replace(",", "")
        .trim()
        .to_string();

    if cleaned.is_empty() {
        return Err(ParseKoppaError::Empty);
    }

    if let Some((whole, fraction)) = cleaned.split_once('.') {
        let whole_units: u128 = if whole.is_empty() {
            0
        } else {
            whole.parse().map_err(|_| ParseKoppaError::InvalidNumber)?
        };

        // Pad or truncate fraction to 9 digits
        let fraction_len = fraction.len();
        let fraction_units: u128 = if fraction_len > KOPPA_DECIMALS as usize {
            // Truncate to 9 decimal places
            let truncated = &fraction[..KOPPA_DECIMALS as usize];
            truncated.parse().map_err(|_| ParseKoppaError::InvalidNumber)?
        } else {
            // Pad with zeros
            let padded = format!("{:0<9}", fraction);
            padded.parse().map_err(|_| ParseKoppaError::InvalidNumber)?
        };

        Ok(whole_units
            .checked_mul(KOPPA_UNIT)
            .ok_or(ParseKoppaError::Overflow)?
            .checked_add(fraction_units)
            .ok_or(ParseKoppaError::Overflow)?)
    } else {
        // No decimal point - whole Koppa
        let whole: u128 = cleaned.parse().map_err(|_| ParseKoppaError::InvalidNumber)?;
        whole
            .checked_mul(KOPPA_UNIT)
            .ok_or(ParseKoppaError::Overflow)
    }
}

/// Error parsing Koppa amount
#[derive(Debug, Clone, PartialEq)]
pub enum ParseKoppaError {
    /// Empty input string
    Empty,
    /// Invalid number format
    InvalidNumber,
    /// Amount would overflow
    Overflow,
}

impl fmt::Display for ParseKoppaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty amount"),
            Self::InvalidNumber => write!(f, "invalid number format"),
            Self::Overflow => write!(f, "amount overflow"),
        }
    }
}

impl std::error::Error for ParseKoppaError {}

/// Format a number with comma separators for thousands.
fn format_with_commas(n: u128) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Wrapper type for displaying Koppa amounts
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Koppa(pub u128);

impl fmt::Display for Koppa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format_koppa(self.0))
    }
}

impl From<u128> for Koppa {
    fn from(base_units: u128) -> Self {
        Self(base_units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_koppa() {
        assert_eq!(format_koppa(0), "0 Ϙ");
        assert_eq!(format_koppa(1), "0.000000001 Ϙ");
        assert_eq!(format_koppa(1_000_000_000), "1 Ϙ");
        assert_eq!(format_koppa(1_500_000_000), "1.5 Ϙ");
        assert_eq!(format_koppa(1_000_000_000_000), "1,000 Ϙ");
        assert_eq!(format_koppa(123_456_789_012_345_678), "123,456,789.012345678 Ϙ");
    }

    #[test]
    fn test_parse_koppa() {
        assert_eq!(parse_koppa("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_koppa("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_koppa("0.1").unwrap(), 100_000_000);
        assert_eq!(parse_koppa("0.001").unwrap(), 1_000_000);
        assert_eq!(parse_koppa("1,000").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_koppa("1.5 Ϙ").unwrap(), 1_500_000_000);
    }

    #[test]
    fn test_format_with_commas() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(123), "123");
        assert_eq!(format_with_commas(1234), "1,234");
        assert_eq!(format_with_commas(1234567890), "1,234,567,890");
    }
}
