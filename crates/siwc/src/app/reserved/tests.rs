use crate::{AppName, ErrorKind};

#[test]
fn blank_letters_and_format_characters_do_not_hide_reserved_names() {
    let mut accepted = Vec::new();
    for blank in [
        '\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}', '\u{200B}', '\u{200C}', '\u{200D}',
        '\u{200E}', '\u{200F}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}',
        '\u{FEFF}',
    ] {
        for name in [format!("ChatGPT{blank}"), format!("Open{blank}AI")] {
            if AppName::new(&name).err().map(|error| error.kind()) != Some(ErrorKind::InvalidInput)
            {
                accepted.push(name);
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "reserved spellings accepted: {accepted:?}"
    );
    assert!(crate::app::is_stored_name("Open\u{3164}AI"));
    let ordinary = "한글\u{3164}노트";
    assert_eq!(AppName::new(ordinary).unwrap().as_str(), ordinary);
}

#[test]
fn combining_marks_in_the_extended_blocks_do_not_hide_reserved_names() {
    let mut accepted = Vec::new();
    for mark in ['\u{1ABF}', '\u{1DE4}', '\u{20DD}', '\u{FE20}'] {
        let name = format!("Co{mark}dex");
        if AppName::new(&name).err().map(|error| error.kind()) != Some(ErrorKind::InvalidInput) {
            accepted.push(mark.escape_unicode().to_string());
        }
    }
    assert!(accepted.is_empty(), "marks accepted in Codex: {accepted:?}");
    assert!(crate::app::is_stored_name("Co\u{1DE4}dex"));
    let ordinary = "Notes\u{1DE4}";
    assert_eq!(AppName::new(ordinary).unwrap().as_str(), ordinary);
}

#[test]
fn combining_cyrillic_letters_do_not_hide_reserved_names() {
    let disguised = "Co\u{2DE0}dex";
    let ordinary = "Заметки\u{2DE0}";
    assert_eq!(AppName::new(ordinary).unwrap().as_str(), ordinary);
    assert!(crate::app::is_stored_name(disguised));
    assert_eq!(
        AppName::new(disguised).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
}

#[test]
fn characters_left_after_folding_cannot_hide_a_whole_ascii_reserved_name() {
    let disguised = [
        "Co\u{2DE0}dex",
        "Co\u{A674}dex",
        "Co\u{A69E}dex",
        "Co\u{05B4}dex",
        "Co\u{0657}dex",
        "Ope\u{0670}nAI",
        "Chat\u{0BC0}GPT",
        "Co日dex",
    ];
    let accepted: Vec<_> = disguised
        .into_iter()
        .filter(|name| {
            AppName::new(name).err().map(|error| error.kind()) != Some(ErrorKind::InvalidInput)
        })
        .collect();
    assert!(
        accepted.is_empty(),
        "reserved spellings accepted: {accepted:?}"
    );
    for name in disguised {
        assert!(crate::app::is_stored_name(name), "{name:?}");
    }
    for name in ["Заметки", "한글 노트", "פתקים", "ملاحظات"] {
        assert_eq!(AppName::new(name).unwrap().as_str(), name);
    }
}

#[test]
fn reserved_names_with_accents_other_scripts_or_styled_letters_are_rejected() {
    let accepted: Vec<_> = [
        "ChâtGPT",
        "Cha\u{0302}tGPT",
        "ÖpenAI",
        "O\u{0308}penAI",
        "Codèx",
        "ꓚꓧꓮꓔꓖꓑꓔ",
        "ⅭhatGPT",
        "chatɡpt",
        "chɑtgpt",
        "sıwc",
        "ᴼᴾᴱᴺᴬᴵ",
        "օpenai",
    ]
    .into_iter()
    .filter(|name| {
        AppName::new(name).err().map(|error| error.kind()) != Some(ErrorKind::InvalidInput)
    })
    .collect();
    assert!(
        accepted.is_empty(),
        "reserved spellings accepted: {accepted:?}"
    );
}

#[test]
fn only_non_ascii_letters_can_stand_in_for_the_allowed_number_of_letters() {
    for name in ["ChâtGṔT", "opénaI", "códex", "siwç"] {
        assert_eq!(
            AppName::new(name).unwrap_err().kind(),
            ErrorKind::InvalidInput,
            "{name}"
        );
    }
    for name in ["ÇhâtGṔT", "öpénaI", "códèx", "sîwç", "ChâtGPx", "ChatGP１"] {
        assert_eq!(AppName::new(name).unwrap().as_str(), name);
    }
}

#[test]
fn ordinary_non_latin_and_accented_latin_names_keep_their_spelling() {
    for name in [
        "さくらノート",
        "Заметки",
        "Ουρανός",
        "ملاحظات",
        "ꓡꓲꓢꓴ",
        "Écritoire",
        "Café Notes",
        "São Bento",
    ] {
        assert_eq!(AppName::new(name).unwrap().as_str(), name);
    }
}
