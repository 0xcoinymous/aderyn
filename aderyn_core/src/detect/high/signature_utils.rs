use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SrcSpan {
    pub(crate) start: usize,
    pub(crate) len: usize,
    pub(crate) file: usize,
}

impl SrcSpan {
    pub(crate) fn parse(src: &str) -> Option<Self> {
        let mut parts = src.split(':');
        Some(Self {
            start: parts.next()?.parse().ok()?,
            len: parts.next()?.parse().ok()?,
            file: parts.next()?.parse().ok()?,
        })
    }

    pub(crate) fn contains(self, other: Self) -> bool {
        self.file == other.file
            && other.start >= self.start
            && other.start.saturating_add(other.len) <= self.start.saturating_add(self.len)
    }
}

pub(crate) fn parse_call_args_at(source: &str, pos: usize) -> Option<Vec<String>> {
    let tail = source.get(pos..)?;
    let open = pos + tail.find('(')?;
    let close = matching_delimiter(source, open, '(', ')')?;
    Some(split_top_level(&source[open + 1..close], ','))
}

pub(crate) fn parse_dynamic_bytes_parameter_names(source: &str) -> Vec<String> {
    parse_parameters(source)
        .into_iter()
        .filter_map(|(raw, name)| {
            let compacted = compact(&raw);
            let is_dynamic_bytes = (compacted.starts_with("bytescalldata")
                || compacted.starts_with("bytesmemory")
                || compacted.starts_with("bytesstorage")
                || compacted.starts_with("bytes"))
                && !compacted.starts_with("bytes1")
                && !compacted.starts_with("bytes2")
                && !compacted.starts_with("bytes3")
                && !compacted.starts_with("bytes4")
                && !compacted.starts_with("bytes5")
                && !compacted.starts_with("bytes6")
                && !compacted.starts_with("bytes7")
                && !compacted.starts_with("bytes8")
                && !compacted.starts_with("bytes9")
                && !compacted.starts_with("bytes10")
                && !compacted.starts_with("bytes11")
                && !compacted.starts_with("bytes12")
                && !compacted.starts_with("bytes13")
                && !compacted.starts_with("bytes14")
                && !compacted.starts_with("bytes15")
                && !compacted.starts_with("bytes16")
                && !compacted.starts_with("bytes17")
                && !compacted.starts_with("bytes18")
                && !compacted.starts_with("bytes19")
                && !compacted.starts_with("bytes20")
                && !compacted.starts_with("bytes21")
                && !compacted.starts_with("bytes22")
                && !compacted.starts_with("bytes23")
                && !compacted.starts_with("bytes24")
                && !compacted.starts_with("bytes25")
                && !compacted.starts_with("bytes26")
                && !compacted.starts_with("bytes27")
                && !compacted.starts_with("bytes28")
                && !compacted.starts_with("bytes29")
                && !compacted.starts_with("bytes30")
                && !compacted.starts_with("bytes31")
                && !compacted.starts_with("bytes32");
            is_dynamic_bytes.then_some(name)
        })
        .collect()
}

fn parse_parameters(source: &str) -> Vec<(String, String)> {
    let Some(function_pos) = find_word_from(source, "function", 0) else {
        return Vec::new();
    };
    let Some(open_rel) = source[function_pos..].find('(') else {
        return Vec::new();
    };
    let open = function_pos + open_rel;
    let Some(close) = matching_delimiter(source, open, '(', ')') else {
        return Vec::new();
    };
    split_top_level(&source[open + 1..close], ',')
        .into_iter()
        .filter_map(|part| {
            let identifiers = identifier_sequence(&part);
            let name = identifiers
                .into_iter()
                .rev()
                .find(|x| !is_type_or_location_keyword(x))?;
            Some((part, name))
        })
        .collect()
}

pub(crate) fn function_name(source: &str) -> Option<String> {
    let function_pos = find_word_from(source, "function", 0)?;
    let after = &source[function_pos + "function".len()..];
    first_identifier(after)
}

pub(crate) fn is_public_or_external(source: &str) -> bool {
    let header = source.split('{').next().unwrap_or(source);
    contains_word(header, "public") || contains_word(header, "external")
}

pub(crate) fn collect_assignments(source: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for statement in split_statements(source) {
        let Some(eq) = find_top_level_operator(&statement, "=") else {
            continue;
        };
        if eq > 0
            && matches!(
                statement.as_bytes().get(eq - 1).copied(),
                Some(b'!' | b'<' | b'>' | b'=')
            )
        {
            continue;
        }
        let lhs = &statement[..eq];
        if lhs.contains('[') || lhs.trim_start().starts_with('(') {
            continue;
        }
        let rhs = statement[eq + 1..].trim().trim_end_matches(';').trim();
        if let Some(name) = last_identifier(lhs) {
            out.insert(name, rhs.to_string());
        }
    }
    out
}

pub(crate) fn expand_expression(
    expression: &str,
    assignments: &HashMap<String, String>,
    depth: usize,
) -> String {
    if depth == 0 {
        return expression.to_string();
    }
    let mut substitutions = HashMap::new();
    for identifier in identifiers_in_text(expression) {
        if let Some(rhs) = assignments.get(&identifier) {
            if compact(rhs) != compact(&identifier) {
                substitutions.insert(
                    identifier,
                    format!("({})", expand_expression(rhs, assignments, depth - 1)),
                );
            }
        }
    }
    substitute_identifiers(expression, &substitutions)
}

pub(crate) fn substitute_identifiers(
    text: &str,
    substitutions: &HashMap<String, String>,
) -> String {
    if substitutions.is_empty() {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let ident = &text[start..i];
            if let Some(replacement) = substitutions.get(ident) {
                out.push_str(replacement);
            } else {
                out.push_str(ident);
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

pub(crate) fn split_statements(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let mut start = 0usize;
    let mut p = 0i32;
    let mut b = 0i32;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escaped = false;

    for (i, ch) in chars.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            if *ch == '\\' {
                escaped = true;
            } else if *ch == quote {
                in_string = false;
            }
            continue;
        }
        match *ch {
            '"' | '\'' => {
                in_string = true;
                quote = *ch;
            }
            '(' => p += 1,
            ')' => p -= 1,
            '[' => b += 1,
            ']' => b -= 1,
            ';' if p == 0 && b == 0 => {
                let statement = chars[start..=i].iter().collect::<String>();
                if !statement.trim().is_empty() {
                    out.push(statement);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < chars.len() {
        let tail = chars[start..].iter().collect::<String>();
        if !tail.trim().is_empty() {
            out.push(tail);
        }
    }
    out
}

pub(crate) fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut p = 0i32;
    let mut b = 0i32;
    let mut c = 0i32;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escaped = false;

    for (i, ch) in chars.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            if *ch == '\\' {
                escaped = true;
            } else if *ch == quote {
                in_string = false;
            }
            continue;
        }
        match *ch {
            '"' | '\'' => {
                in_string = true;
                quote = *ch;
            }
            '(' => p += 1,
            ')' => p -= 1,
            '[' => b += 1,
            ']' => b -= 1,
            '{' => c += 1,
            '}' => c -= 1,
            x if x == separator && p == 0 && b == 0 && c == 0 => {
                out.push(chars[start..i].iter().collect::<String>().trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(chars[start..].iter().collect::<String>().trim().to_string());
    out
}

pub(crate) fn matching_delimiter(
    text: &str,
    open: usize,
    open_ch: char,
    close_ch: char,
) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open).copied()? as char != open_ch {
        return None;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut quote = b'\0';
    let mut i = open;
    while i < bytes.len() {
        let ch = bytes[i];
        if in_string {
            if ch == quote && (i == 0 || bytes[i - 1] != b'\\') {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if ch == b'"' || ch == b'\'' {
            in_string = true;
            quote = ch;
        } else if ch as char == open_ch {
            depth += 1;
        } else if ch as char == close_ch {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub(crate) fn find_top_level_operator(text: &str, operator: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let op = operator.as_bytes();
    let mut p = 0i32;
    let mut b = 0i32;
    let mut i = 0;
    while i + op.len() <= bytes.len() {
        match bytes[i] {
            b'(' => p += 1,
            b')' => p -= 1,
            b'[' => b += 1,
            b']' => b -= 1,
            _ => {}
        }
        if p == 0 && b == 0 && &bytes[i..i + op.len()] == op {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub(crate) fn identifier_sequence(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            out.push(text[start..i].to_string());
        } else {
            i += 1;
        }
    }
    out
}

pub(crate) fn identifiers_in_text(text: &str) -> BTreeSet<String> {
    identifier_sequence(text)
        .into_iter()
        .filter(|x| !is_language_keyword(x))
        .collect()
}

pub(crate) fn first_identifier(text: &str) -> Option<String> {
    identifier_sequence(text)
        .into_iter()
        .find(|x| !is_language_keyword(x))
}

pub(crate) fn last_identifier(text: &str) -> Option<String> {
    identifier_sequence(text)
        .into_iter()
        .rev()
        .find(|x| !is_language_keyword(x))
}

pub(crate) fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

pub(crate) fn contains_word(text: &str, word: &str) -> bool {
    find_word_from(text, word, 0).is_some()
}

pub(crate) fn find_word_from(text: &str, word: &str, from: usize) -> Option<usize> {
    if word.is_empty() || from >= text.len() {
        return None;
    }
    let mut offset = from;
    while let Some(rel) = text[offset..].find(word) {
        let pos = offset + rel;
        let before_ok = pos == 0
            || !text
                .as_bytes()
                .get(pos - 1)
                .copied()
                .is_some_and(is_ident_continue);
        let end = pos + word.len();
        let after_ok = end >= text.len()
            || !text
                .as_bytes()
                .get(end)
                .copied()
                .is_some_and(is_ident_continue);
        if before_ok && after_ok {
            return Some(pos);
        }
        offset = end;
        if offset >= text.len() {
            break;
        }
    }
    None
}

fn is_ident_start(ch: u8) -> bool {
    ch == b'_' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: u8) -> bool {
    ch == b'_' || ch.is_ascii_alphanumeric()
}

fn is_type_or_location_keyword(word: &str) -> bool {
    matches!(
        word,
        "address"
            | "bool"
            | "bytes"
            | "bytes1"
            | "bytes2"
            | "bytes3"
            | "bytes4"
            | "bytes5"
            | "bytes6"
            | "bytes7"
            | "bytes8"
            | "bytes9"
            | "bytes10"
            | "bytes11"
            | "bytes12"
            | "bytes13"
            | "bytes14"
            | "bytes15"
            | "bytes16"
            | "bytes17"
            | "bytes18"
            | "bytes19"
            | "bytes20"
            | "bytes21"
            | "bytes22"
            | "bytes23"
            | "bytes24"
            | "bytes25"
            | "bytes26"
            | "bytes27"
            | "bytes28"
            | "bytes29"
            | "bytes30"
            | "bytes31"
            | "bytes32"
            | "string"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uint128"
            | "uint256"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "int128"
            | "int256"
            | "calldata"
            | "memory"
            | "storage"
            | "payable"
    )
}

fn is_language_keyword(word: &str) -> bool {
    matches!(
        word,
        "abi"
            | "address"
            | "assert"
            | "block"
            | "bool"
            | "break"
            | "bytes"
            | "calldata"
            | "contract"
            | "continue"
            | "delete"
            | "else"
            | "emit"
            | "external"
            | "false"
            | "for"
            | "function"
            | "if"
            | "internal"
            | "keccak256"
            | "memory"
            | "msg"
            | "payable"
            | "private"
            | "public"
            | "pure"
            | "require"
            | "return"
            | "returns"
            | "revert"
            | "sha256"
            | "storage"
            | "string"
            | "this"
            | "true"
            | "try"
            | "tx"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uint128"
            | "uint256"
            | "view"
            | "while"
    )
}
