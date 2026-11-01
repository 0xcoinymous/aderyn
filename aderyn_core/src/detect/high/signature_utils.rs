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

/// Names of the named return variables, e.g. `current` in `returns (uint256 current)`.
pub(crate) fn named_return_variables(source: &str) -> Vec<String> {
    let header = source.split('{').next().unwrap_or(source);
    let Some(returns_pos) = find_word_from(header, "returns", 0) else {
        return Vec::new();
    };
    let Some(open_rel) = header[returns_pos..].find('(') else {
        return Vec::new();
    };
    let open = returns_pos + open_rel;
    let Some(close) = matching_delimiter(header, open, '(', ')') else {
        return Vec::new();
    };
    split_top_level(&header[open + 1..close], ',')
        .into_iter()
        .filter_map(|part| {
            let identifiers = identifier_sequence(&part);
            if identifiers.len() < 2 {
                return None;
            }
            identifiers
                .into_iter()
                .rev()
                .find(|x| !is_type_or_location_keyword(x))
        })
        .collect()
}

/// Expressions a function returns: the operands of its `return` statements and the values assigned to
/// its named return variables.
pub(crate) fn returned_expressions(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for statement in split_statements(source) {
        if let Some(pos) = find_word_from(&statement, "return", 0) {
            let expression = statement[pos + "return".len()..].trim().trim_end_matches(';').trim();
            if !expression.is_empty() {
                out.push(expression.to_string());
            }
        }
    }
    let assignments = collect_assignments(source);
    for name in named_return_variables(source) {
        if let Some(rhs) = assignments.get(&name) {
            out.push(rhs.clone());
        }
    }
    out
}

/// The operand that ends just before byte `end`, e.g. `nonces[owner]` in `nonces[owner]++` or
/// `self.nonce` in `self.nonce.increment()`. Empty when there is none.
pub(crate) fn operand_before(text: &str, end: usize) -> String {
    let bytes = text.as_bytes();
    let mut i = end.min(bytes.len());
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let stop = i;
    while i > 0 {
        let ch = bytes[i - 1];
        if ch == b']' {
            let mut depth = 0i32;
            let mut j = i;
            while j > 0 {
                j -= 1;
                match bytes[j] {
                    b']' => depth += 1,
                    b'[' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                break;
            }
            i = j;
        } else if is_ident_continue(ch) || ch == b'.' {
            i -= 1;
        } else {
            break;
        }
    }
    text[i..stop].trim_start_matches('.').to_string()
}

/// The operand that starts at byte `start`, e.g. `nonce` in `++nonce`. Empty when there is none.
pub(crate) fn operand_after(text: &str, start: usize) -> String {
    let bytes = text.as_bytes();
    let mut i = start.min(bytes.len());
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let begin = i;
    while i < bytes.len() {
        let ch = bytes[i];
        if ch == b'[' {
            match matching_delimiter(text, i, '[', ']') {
                Some(close) => i = close + 1,
                None => break,
            }
        } else if is_ident_continue(ch) || ch == b'.' {
            i += 1;
        } else {
            break;
        }
    }
    text[begin..i].to_string()
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

/// Longest expansion of one variable that is substituted; a longer one leaves the variable as it is.
/// Chains of assignments that use the previous variable several times grow exponentially otherwise.
pub(crate) const MAX_EXPANSION_LEN: usize = 1 << 18;

pub(crate) fn expand_expression(
    expression: &str,
    assignments: &HashMap<String, String>,
    depth: usize,
) -> String {
    expand_memoized(expression, assignments, depth, &mut HashMap::new())
}

/// The expansion of a variable depends only on the variable and the remaining depth, so each pair is
/// expanded once per call.
fn expand_memoized(
    expression: &str,
    assignments: &HashMap<String, String>,
    depth: usize,
    memo: &mut HashMap<(String, usize), Option<String>>,
) -> String {
    if depth == 0 {
        return expression.to_string();
    }
    let mut substitutions = HashMap::new();
    for identifier in identifiers_in_text(expression) {
        if let Some(rhs) = assignments.get(&identifier) {
            if compact(rhs) != compact(&identifier) {
                let key = (identifier.clone(), depth);
                if !memo.contains_key(&key) {
                    let inner = expand_memoized(rhs, assignments, depth - 1, memo);
                    let replacement = (inner.len() <= MAX_EXPANSION_LEN).then(|| format!("({inner})"));
                    memo.insert(key.clone(), replacement);
                }
                if let Some(replacement) = &memo[&key] {
                    substitutions.insert(identifier, replacement.clone());
                }
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

/// Splits a statement at block braces outside parentheses, so that `if (c) { x = a; } y = b`, a
/// function header followed by its first statement, or an inline-assembly block followed by a
/// declaration yields one piece per statement.
pub(crate) fn block_pieces(statement: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in statement.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            '{' | '}' if depth == 0 => {
                out.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    out.push(current);
    out.retain(|piece| !piece.trim().is_empty());
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
            // The tail of a number literal (`x7fff…` in `0x7fff…`, `e18` in `1e18`) is not an identifier.
            if start > 0 && bytes[start - 1].is_ascii_digit() {
                continue;
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

/// The variable that receives the recovered signer, as in `address signatory = ecrecover(...)`. The
/// recovered address is the signer by definition, so state keyed by it (`nonces[signatory]++`) is the
/// signer's own namespace even when the address is never compared with a signed parameter.
pub(crate) fn recovered_into_variable(source: &str, pos: usize) -> Option<String> {
    let before = source.get(..pos)?;
    let start = before.rfind([';', '{', '}']).map_or(0, |i| i + 1);
    let mut statement = before[start..].trim();
    // Drop a qualifier chain in front of a member call: `ECDSA.`, `hash.`, `digest.toEth...().`.
    while let Some(rest) = statement.strip_suffix('.') {
        let mut rest = rest.trim_end();
        if rest.ends_with(')') {
            let mut depth = 0i32;
            let mut cut = None;
            for (i, ch) in rest.char_indices().rev() {
                match ch {
                    ')' => depth += 1,
                    '(' => {
                        depth -= 1;
                        if depth == 0 {
                            cut = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest = rest[..cut?].trim_end();
        }
        let ident_start = rest
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        if ident_start == rest.len() {
            return None;
        }
        statement = rest[..ident_start].trim_end();
    }
    let lhs = statement.strip_suffix('=')?.trim_end();
    if lhs.ends_with(['=', '!', '<', '>']) {
        return None;
    }
    let mut words = lhs.split_whitespace().filter(|w| !matches!(*w, "address" | "payable"));
    let name = words.next()?;
    if words.next().is_some()
        || name.is_empty()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || name.as_bytes()[0].is_ascii_digit()
    {
        return None;
    }
    Some(name.to_string())
}

/// Writes SafeMath calls as operators: `x.add(y)` -> `x+(y)`, `x.sub(y)` -> `x-(y)` and
/// `SafeMath.add(x, y)` -> `(x)+(y)`, so that `nonces[a] = nonces[a].add(1)` reads as an increment.
pub(crate) fn desugar_safemath(expression: &str) -> String {
    let mut text = expression.to_string();
    for (method, op) in [("add", '+'), ("sub", '-')] {
        let library_call = format!("SafeMath.{method}(");
        while let Some(start) = text.find(&library_call) {
            let open = start + library_call.len() - 1;
            let Some(close) = matching_delimiter(&text, open, '(', ')') else { break };
            let args = split_top_level(&text[open + 1..close], ',');
            if args.len() != 2 {
                break;
            }
            let replaced = format!("({}){op}({})", args[0].trim(), args[1].trim());
            text.replace_range(start..=close, &replaced);
        }
        let member_call = format!(".{method}(");
        while let Some(dot) = text.find(&member_call) {
            let open = dot + member_call.len() - 1;
            let Some(close) = matching_delimiter(&text, open, '(', ')') else { break };
            let replaced = format!("{op}({})", &text[open + 1..close]);
            text.replace_range(dot..=close, &replaced);
        }
    }
    text
}

/// The source with every comment replaced by spaces (line breaks kept), so offsets stay valid and
/// text in comments (`// increase nonce (to avoid re-use)`, commented-out checks) is never analysed.
/// String literals are skipped, so `"https://..."` is not taken for a comment.
pub(crate) fn blank_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = source[i + 2..].find("*/").map_or(bytes.len(), |p| i + 2 + p + 2);
                for byte in &mut out[i..end] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    // Every byte of a comment, including the bytes of multi-byte characters, became a space, so the
    // text is still valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// Whether `pos` lies in the body of an `if` or `else`: the block right after the condition, or
/// the single statement when there is no block. `if`/`else` must be whole words (not `verify`), and an
/// `unchecked { }` block after `if (..) revert ..;` is not the body of that `if`.
pub(crate) fn inside_conditional_body(source: &str, pos: usize) -> bool {
    let bytes = source.as_bytes();
    let pos = pos.min(source.len());
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let body_contains = |after: usize| -> bool {
        let rest = &source[after..];
        let skip = rest.len() - rest.trim_start().len();
        let start = after + skip;
        if bytes.get(start) == Some(&b'{') {
            return matching_delimiter(source, start, '{', '}').is_some_and(|end| pos > start && pos < end);
        }
        // Single statement: up to the next `;` outside brackets.
        let mut depth = 0i32;
        for (i, ch) in source[start..].char_indices() {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ';' if depth <= 0 => return pos >= start && pos <= start + i,
                _ => {}
            }
        }
        false
    };
    let mut i = 0;
    while i < pos {
        let word_start = i == 0 || !is_ident(bytes[i - 1]);
        if word_start && bytes[i..].starts_with(b"if") && !bytes.get(i + 2).is_some_and(|b| is_ident(*b)) {
            let rest = &source[i + 2..];
            let open = i + 2 + (rest.len() - rest.trim_start().len());
            if bytes.get(open) == Some(&b'(') {
                if let Some(close) = matching_delimiter(source, open, '(', ')') {
                    if close < pos && body_contains(close + 1) {
                        return true;
                    }
                }
            }
        }
        if word_start && bytes[i..].starts_with(b"else") && !bytes.get(i + 4).is_some_and(|b| is_ident(*b)) {
            let rest = &source[i + 4..];
            let next = rest.trim_start();
            if !next.starts_with("if") && body_contains(i + 4) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// The body after an `if (..)` stops execution: `revert`, `throw`, `return false`, or a block that
/// starts with one of them.
pub(crate) fn body_reverts(after_condition: &str) -> bool {
    let body = after_condition.trim_start();
    let body = body.strip_prefix('{').map_or(body, str::trim_start);
    let compacted = compact(body);
    body.starts_with("revert")
        || body.starts_with("throw")
        || compacted.starts_with("returnfalse;")
        || compacted.starts_with("return(false);")
}

/// The logical negation of a condition, with De Morgan for `||`/`&&` and inverted comparisons, so that
/// `if (cond) revert` can be read as `require(negate_condition(cond))`.
pub(crate) fn negate_condition(condition: &str) -> String {
    let mut c = condition.trim();
    while c.starts_with('(') && matching_delimiter(c, 0, '(', ')') == Some(c.len() - 1) {
        c = c[1..c.len() - 1].trim();
    }
    for (op, join) in [("||", " && "), ("&&", " || ")] {
        let mut parts = Vec::new();
        let mut rest = c;
        while let Some(idx) = find_top_level_operator(rest, op) {
            parts.push(rest[..idx].to_string());
            rest = &rest[idx + 2..];
        }
        if !parts.is_empty() {
            parts.push(rest.to_string());
            return parts.iter().map(|p| negate_condition(p)).collect::<Vec<_>>().join(join);
        }
    }
    for (op, inverse) in [("!=", "=="), ("==", "!="), (">=", "<"), ("<=", ">"), (">", "<="), ("<", ">=")] {
        if let Some(idx) = find_top_level_operator(c, op) {
            return format!("{} {inverse} {}", c[..idx].trim(), c[idx + op.len()..].trim());
        }
    }
    match c.strip_prefix('!') {
        Some(inner) if !inner.starts_with('=') => inner.trim().to_string(),
        _ => format!("!{c}"),
    }
}

/// The digest of a member recovery call that starts at `pos`: the first argument for a library call
/// (`ECDSA.recover(hash, sig)`), and the receiver for a `using ECDSA for bytes32` call
/// (`hash.recover(sig)`, `keccak256(..).toEthSignedMessageHash().recover(sig)`).
pub(crate) fn member_recovery_digest(source: &str, pos: usize, member: &str) -> Option<String> {
    let needle = format!(".{member}(");
    let tail = source.get(pos..)?;
    let dot = pos + tail.find(&needle)?;
    let receiver = source[pos..dot].trim();
    let args = parse_call_args_at(source, dot)?;
    let is_library = !receiver.is_empty()
        && receiver.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && receiver.as_bytes()[0].is_ascii_uppercase();
    if is_library || receiver.is_empty() {
        args.first().cloned()
    } else {
        Some(receiver.to_string())
    }
}

/// The receiver and arguments of a member call `receiver.member(args)` whose expression starts at
/// `pos`. The receiver is `None` for a library or contract name (`ECDSA.recover(..)`).
pub(crate) fn member_call_parts(source: &str, pos: usize, member: &str) -> Option<(Option<String>, Vec<String>)> {
    let tail = source.get(pos..)?;
    let dot = pos + tail.find(&format!(".{member}("))?;
    let receiver = source[pos..dot].trim();
    let args = parse_call_args_at(source, dot)?;
    let is_type_name = receiver.is_empty()
        || (receiver.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && receiver.as_bytes()[0].is_ascii_uppercase());
    Some(((!is_type_name).then(|| receiver.to_string()), args))
}
