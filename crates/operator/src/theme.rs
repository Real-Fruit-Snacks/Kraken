//! Catppuccin Mocha theme for Kraken CLI

use console::{style, Color, Style, Term};

/// Catppuccin Mocha RGB color values
#[allow(dead_code)]
pub mod colors {
    use super::Color;

    pub const ROSEWATER: Color = Color::Color256(217);
    pub const FLAMINGO: Color = Color::Color256(210);
    pub const PINK: Color = Color::Color256(212);
    pub const MAUVE: Color = Color::Color256(183);
    pub const RED: Color = Color::Color256(204);
    pub const MAROON: Color = Color::Color256(210);
    pub const PEACH: Color = Color::Color256(215);
    pub const YELLOW: Color = Color::Color256(229);
    pub const GREEN: Color = Color::Color256(156);
    pub const TEAL: Color = Color::Color256(123);
    pub const SKY: Color = Color::Color256(117);
    pub const SAPPHIRE: Color = Color::Color256(74);
    pub const BLUE: Color = Color::Color256(111);
    pub const LAVENDER: Color = Color::Color256(147);
    pub const TEXT: Color = Color::Color256(189);
    pub const SUBTEXT1: Color = Color::Color256(145);
    pub const SUBTEXT0: Color = Color::Color256(109);
    pub const OVERLAY2: Color = Color::Color256(102);
    pub const OVERLAY1: Color = Color::Color256(95);
    pub const OVERLAY0: Color = Color::Color256(60);
    pub const SURFACE2: Color = Color::Color256(59);
    pub const SURFACE1: Color = Color::Color256(59);
    pub const SURFACE0: Color = Color::Color256(59);
    pub const BASE: Color = Color::Color256(234);
    pub const MANTLE: Color = Color::Color256(233);
    pub const CRUST: Color = Color::Color256(232);
}

/// Theme helper functions for CLI output
pub struct Theme;

impl Theme {
    /// Check if stdout is an interactive terminal
    pub fn is_interactive() -> bool {
        Term::stdout().is_term()
    }

    /// Prompt "kraken" text (Mauve, bold)
    pub fn prompt() -> Style {
        Style::new().fg(colors::MAUVE).bold()
    }

    /// Session ID in prompt (Peach)
    pub fn prompt_session() -> Style {
        Style::new().fg(colors::PEACH)
    }

    /// Prompt arrow ">" (Green)
    pub fn prompt_arrow() -> Style {
        Style::new().fg(colors::GREEN)
    }

    /// Success message [+] (Green)
    #[allow(dead_code)]
    pub fn success() -> Style {
        Style::new().fg(colors::GREEN)
    }

    /// Error message [-] (Red)
    #[allow(dead_code)]
    pub fn error() -> Style {
        Style::new().fg(colors::RED)
    }

    /// Warning message [!] (Yellow)
    #[allow(dead_code)]
    pub fn warning() -> Style {
        Style::new().fg(colors::YELLOW)
    }

    /// Info message [*] (Blue)
    #[allow(dead_code)]
    pub fn info() -> Style {
        Style::new().fg(colors::BLUE)
    }

    /// Dimmed/secondary text (Subtext0)
    #[allow(dead_code)]
    pub fn dim() -> Style {
        Style::new().fg(colors::SUBTEXT0)
    }

    /// Table header (Lavender, bold)
    #[allow(dead_code)]
    pub fn header() -> Style {
        Style::new().fg(colors::LAVENDER).bold()
    }

    /// Banner ASCII art (Mauve)
    #[allow(dead_code)]
    pub fn banner() -> Style {
        Style::new().fg(colors::MAUVE)
    }

    /// Command name in help (Teal)
    #[allow(dead_code)]
    pub fn command() -> Style {
        Style::new().fg(colors::TEAL)
    }

    /// Argument placeholder in help (Peach)
    #[allow(dead_code)]
    pub fn argument() -> Style {
        Style::new().fg(colors::PEACH)
    }

    /// Normal text (Text)
    #[allow(dead_code)]
    pub fn text() -> Style {
        Style::new().fg(colors::TEXT)
    }

    /// Implant state color
    pub fn implant_state(state: &str) -> Style {
        match state {
            "active" => Style::new().fg(colors::GREEN),
            "staging" => Style::new().fg(colors::BLUE),
            "lost" => Style::new().fg(colors::YELLOW),
            "burned" => Style::new().fg(colors::RED),
            "retired" => Style::new().fg(colors::SUBTEXT0),
            _ => Style::new().fg(colors::TEXT),
        }
    }

    /// Job/Task status color
    pub fn status_color(status: &str) -> Style {
        match status {
            "running" => Style::new().fg(colors::YELLOW),
            "completed" => Style::new().fg(colors::GREEN),
            "failed" => Style::new().fg(colors::RED),
            "cancelled" => Style::new().fg(colors::SUBTEXT0),
            "queued" => Style::new().fg(colors::BLUE),
            "dispatched" => Style::new().fg(colors::PEACH),
            _ => Style::new().fg(colors::TEXT),
        }
    }
}

/// Print styled success message with [+] prefix
pub fn print_success(msg: &str) {
    if Theme::is_interactive() {
        println!("{} {}", style("[+]").fg(colors::GREEN).bold(), msg);
    } else {
        println!("[+] {}", msg);
    }
}

/// Print styled error message with [-] prefix
pub fn print_error(msg: &str) {
    if Theme::is_interactive() {
        eprintln!("{} {}", style("[-]").fg(colors::RED).bold(), msg);
    } else {
        eprintln!("[-] {}", msg);
    }
}

/// Print styled info message with [*] prefix
pub fn print_info(msg: &str) {
    if Theme::is_interactive() {
        println!("{} {}", style("[*]").fg(colors::BLUE).bold(), msg);
    } else {
        println!("[*] {}", msg);
    }
}

/// Print styled warning message with [!] prefix
#[allow(dead_code)]
pub fn print_warning(msg: &str) {
    if Theme::is_interactive() {
        println!("{} {}", style("[!]").fg(colors::YELLOW).bold(), msg);
    } else {
        println!("[!] {}", msg);
    }
}
