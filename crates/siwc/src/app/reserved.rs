//! The name policy for the provider's products and this library.

#[cfg(test)]
mod tests;

pub(super) const NAMES: [&str; 4] = ["siwc", "chatgpt", "openai", "codex"];

pub(super) fn new_name(name: &str) -> bool {
    // Fold styled letters before filtering out punctuation. Strip marks
    // after lowercasing so the dot produced by U+0130 is ignored too.
    let folded: Vec<char> = letters(name.chars().filter(|&c| !blank(c)).map(fold_letter))
        .filter(|&c| !combining_mark(c))
        .collect();
    NAMES.iter().any(|word| {
        matches_reserved(&folded, word)
            || folded
                .iter()
                .copied()
                .filter(char::is_ascii)
                .eq(word.chars())
    })
}

fn blank(c: char) -> bool {
    matches!(
        c,
        '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
            | '\u{200B}'..='\u{200F}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}'
    )
}

fn combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}' | '\u{2DE0}'..='\u{2DFF}' | '\u{FE20}'..='\u{FE2F}'
    )
}

pub(super) fn stored_name(name: &str) -> bool {
    // A stronger comparison must not invalidate an existing registration.
    let folded: String = letters(name.chars()).collect();
    NAMES.contains(&folded.as_str())
}

fn letters(characters: impl Iterator<Item = char>) -> impl Iterator<Item = char> {
    characters
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
}

fn matches_reserved(folded: &[char], word: &str) -> bool {
    if folded.len() != word.len() {
        return false;
    }
    let mut exact = 0;
    for (&letter, expected) in folded.iter().zip(word.bytes()) {
        if letter == char::from(expected) {
            exact += 1;
        } else if letter.is_ascii() || !letter.is_alphabetic() {
            return false;
        }
    }
    let allowed = if word.len() >= 7 { 2 } else { 1 };
    exact >= word.len() - allowed
}

/// Fold selected look-alikes for this comparison alone.
fn fold_letter(c: char) -> char {
    match unstyled(c) {
        'А' | 'а' | 'Α' | 'α' | 'ᴀ' | 'Ꭺ' | 'ꭺ' | 'ꓮ' | 'ᴬ' => 'a',
        'ꓐ' | 'ᴮ' => 'b',
        'С' | 'с' | 'Ϲ' | 'ϲ' | 'ᴄ' | 'Ꮯ' | 'ꮯ' | 'ℂ' | 'ℭ' | 'ꓚ' => 'c',
        'Ԁ' | 'ԁ' | 'ᴅ' | 'Ꭰ' | 'ꭰ' | 'Ꮷ' | 'ꮷ' | 'ⅅ' | 'ⅆ' | 'ꓓ' | 'ᴰ' => 'd',
        'Е' | 'е' | 'Ε' | 'ε' | 'ᴇ' | 'Ꭼ' | 'ꭼ' | 'ℯ' | 'ℰ' | 'ⅇ' | 'ꓰ' | 'ᴱ' => {
            'e'
        }
        'ꓝ' => 'f',
        'Ԍ' | 'ԍ' | 'ɢ' | 'Ꮐ' | 'ꮐ' | 'Ᏻ' | 'ᏻ' | 'ℊ' | 'ꓖ' | 'ᴳ' => 'g',
        'Н' | 'н' | 'Һ' | 'һ' | 'Η' | 'ʜ' | 'Ꮋ' | 'ꮋ' | 'Ꮒ' | 'ꮒ' | 'ℋ' | 'ℌ' | 'ℍ' | 'ℎ' | 'ꓧ'
        | 'ᴴ' => 'h',
        'І' | 'і' | 'Ι' | 'ι' | 'ɪ' | 'Ꭵ' | 'ꭵ' | 'ℐ' | 'ℑ' | 'ⅈ' | '𝚤' | 'ꓲ' | 'ᴵ' => {
            'i'
        }
        'ꓙ' | 'ᴶ' => 'j',
        'ꓗ' | 'ᴷ' => 'k',
        'ꓡ' | 'ᴸ' => 'l',
        'ꓟ' | 'ᴹ' => 'm',
        'Ν' | 'η' | 'ɴ' | 'ℕ' | 'ꓠ' | 'ᴺ' => 'n',
        'О' | 'о' | 'Ο' | 'ο' | 'ᴏ' | 'ℴ' | 'ꓳ' | 'ᴼ' => 'o',
        'Р' | 'р' | 'Ρ' | 'ρ' | 'ᴘ' | 'Ꮲ' | 'ꮲ' | 'ℙ' | 'ꓑ' | 'ᴾ' => 'p',
        'ꓣ' | 'ᴿ' => 'r',
        'Ѕ' | 'ѕ' | 'ꜱ' | 'Ꮥ' | 'ꮥ' | 'Ꮪ' | 'ꮪ' | 'ꓢ' => 's',
        'Т' | 'т' | 'Τ' | 'τ' | 'ᴛ' | 'Ꭲ' | 'ꭲ' | 'ꓔ' | 'ᵀ' => 't',
        'ꓴ' | 'ᵁ' => 'u',
        'ꓦ' => 'v',
        'Ԝ' | 'ԝ' | 'ω' | 'ᴡ' | 'Ꮃ' | 'ꮃ' | 'Ꮤ' | 'ꮤ' | 'ꓪ' | 'ᵂ' => 'w',
        'Х' | 'х' | 'Χ' | 'χ' | 'ꓫ' => 'x',
        'ꓬ' => 'y',
        'ꓜ' => 'z',
        'ᴭ' => 'Æ',
        'ᴲ' => 'Ǝ',
        'ᴽ' => 'Ȣ',
        other => other,
    }
}

fn unstyled(c: char) -> char {
    let code = u32::from(c);
    let letter = match code {
        0xFF01..=0xFF5E => code - 0xFEE0,
        // Each mathematical Latin style has 26 uppercase and 26 lowercase
        // positions. Skip unassigned positions, whose letters live in
        // Letterlike Symbols and are handled in the table above.
        0x1D400..=0x1D6A3 if c.is_alphabetic() => u32::from('a') + (code - 0x1D400) % 26,
        // Mathematical Greek repeats its letter and symbol slots every 58
        // code points. Restore ordinary Greek for the look-alike table.
        0x1D6A8..=0x1D7C9 => match (code - 0x1D6A8) % 58 {
            offset @ (0..=16 | 18..=24) => 0x0391 + offset,
            offset @ 26..=50 => 0x03B1 + offset - 26,
            _ => code,
        },
        0x249C..=0x24E9 => u32::from('a') + (code - 0x249C) % 26,
        0x1F110..=0x1F129 => u32::from('a') + (code - 0x1F110),
        0x1F130..=0x1F149 => u32::from('a') + (code - 0x1F130),
        0x1F150..=0x1F169 => u32::from('a') + (code - 0x1F150),
        0x1F170..=0x1F189 => u32::from('a') + (code - 0x1F170),
        _ => code,
    };
    char::from_u32(letter).unwrap_or(c)
}
