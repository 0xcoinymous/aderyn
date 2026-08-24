use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
};

use crate::{
    ast::NodeID,
    capture,
    context::{browser::Peek, workspace::WorkspaceContext},
    detect::detector::{IssueDetector, IssueDetectorNamePool, IssueSeverity},
};

use super::signature_utils::{
    collect_assignments, compact, expand_expression, find_word_from, function_name,
    identifiers_in_text, is_public_or_external, matching_delimiter, parse_call_args_at,
    parse_dynamic_bytes_parameter_names, split_statements, SrcSpan,
};

/// Detects semantic ECDSA signature-malleability hazards rather than merely flagging the
/// `ecrecover` primitive.
///
/// The detector focuses on four classes:
/// 1. raw recovery that accepts non-canonical/high-s signatures;
/// 2. permissive or lossy v/recovery-parity normalization;
/// 3. multiple serialized representations when serialization identity is security-sensitive; and
/// 4. raw signature bytes/components hashed and used as a one-time/replay identity.
///
/// Aderyn v0.6.8 does not expose SSA/CFG APIs to detectors, so this implementation combines AST
/// discovery (functions, ecrecover/member accesses, referenced declarations) with a bounded,
/// Solidity-aware source/data-flow pass. It never relies on benchmark filenames, detector-family
/// prefixes, contract names, or exact benchmark variable names.
#[derive(Default)]
pub struct SignatureMalleabilityDetector {
    found_instances: BTreeMap<(String, usize, String), NodeID>,
}

#[derive(Debug, Clone)]
struct CallSite {
    callee: NodeID,
    args: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CryptoSummary {
    signature_verification: bool,
    unsafe_high_s: bool,
    permissive_v: bool,
    flexible_encoding: bool,
}

impl CryptoSummary {
    fn merge_from(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.signature_verification |= other.signature_verification;
        self.unsafe_high_s |= other.unsafe_high_s;
        self.permissive_v |= other.permissive_v;
        self.flexible_encoding |= other.flexible_encoding;
        *self != before
    }
}

#[derive(Debug, Clone)]
struct FunctionModel {
    id: NodeID,
    scope: NodeID,
    source: String,
    entry_point: bool,
    direct: CryptoSummary,
    calls: Vec<CallSite>,
    exact_signature_lengths: BTreeSet<u64>,
    signature_components: BTreeSet<String>,
}

impl IssueDetector for SignatureMalleabilityDetector {
    fn detect(&mut self, context: &WorkspaceContext) -> Result<bool, Box<dyn Error>> {
        let models = build_models(context);
        if models.is_empty() {
            return Ok(false);
        }

        let summaries = propagate_crypto_summaries(&models);
        let mut vulnerable = BTreeSet::new();

        for model in models.values() {
            if !model.entry_point {
                continue;
            }

            let summary = summaries.get(&model.id).cloned().unwrap_or_default();
            if !summary.signature_verification {
                continue;
            }

            let signature_identity = uses_signature_serialization_as_security_identity(
                model,
                &summary,
                &models,
                &summaries,
            );

            // Class 1: high-s / non-canonical s accepted on a signature-authenticated path.
            if summary.unsafe_high_s {
                vulnerable.insert(model.id);
                continue;
            }

            // Class 2: lossy/permissive v normalization accepts multiple representations or maps
            // invalid values onto a valid recovery parity.
            if summary.permissive_v {
                vulnerable.insert(model.id);
                continue;
            }

            // Class 3: accepting multiple encodings is not inherently a vulnerability. It becomes
            // security-sensitive when the application treats the serialized signature as the
            // authorization/replay identity rather than using a canonical message-derived key.
            if summary.flexible_encoding && signature_identity {
                vulnerable.insert(model.id);
                continue;
            }

            // Class 4: raw signature identity combined with any recovery path that is not proven
            // canonical is dangerous. The first two conditions above already capture most of these
            // cases; this branch covers wrapper/library forms whose local source only exposes the
            // serialization-sensitive uniqueness logic.
            if signature_identity
                && !path_is_proven_canonical(model.id, &models, &summaries, &mut BTreeSet::new(), 5)
            {
                vulnerable.insert(model.id);
            }
        }

        // Cross-entry-point representation ambiguity: separate 64-byte and 65-byte entry points in
        // the same contract can accept the same authorization while maintaining independent raw
        // signature identities. This is intentionally conditioned on serialized-signature identity,
        // so legitimate compact/traditional APIs keyed by nonce/digest remain safe.
        let entries: Vec<&FunctionModel> = models.values().filter(|m| m.entry_point).collect();
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                let a = entries[i];
                let b = entries[j];
                if a.scope != b.scope {
                    continue;
                }
                let a_summary = summaries.get(&a.id).cloned().unwrap_or_default();
                let b_summary = summaries.get(&b.id).cloned().unwrap_or_default();
                if !a_summary.signature_verification || !b_summary.signature_verification {
                    continue;
                }
                if !uses_signature_serialization_as_security_identity(
                    a,
                    &a_summary,
                    &models,
                    &summaries,
                ) || !uses_signature_serialization_as_security_identity(
                    b,
                    &b_summary,
                    &models,
                    &summaries,
                ) {
                    continue;
                }

                let a64 = a.exact_signature_lengths.contains(&64);
                let a65 = a.exact_signature_lengths.contains(&65);
                let b64 = b.exact_signature_lengths.contains(&64);
                let b65 = b.exact_signature_lengths.contains(&65);
                if (a64 && b65) || (a65 && b64) {
                    vulnerable.insert(a.id);
                    vulnerable.insert(b.id);
                }
            }
        }

        for function in context.function_definitions() {
            if vulnerable.contains(&function.id) {
                capture!(self, context, function);
            }
        }

        Ok(!self.found_instances.is_empty())
    }

    fn severity(&self) -> IssueSeverity {
        // Aderyn v0.6.8 has only Low/High issue severities. This detector is intentionally High
        // because it reports semantic malleability on authorization paths (including replay-key
        // bypass), not merely the presence of ecrecover.
        IssueSeverity::High
    }

    fn title(&self) -> String {
        String::from("Signature Malleability Vulnerability")
    }

    fn description(&self) -> String {
        String::from(
            "A signature-authenticated operation accepts a non-canonical ECDSA signature, performs \
             permissive recovery-parity normalization, or treats a non-canonical serialized \
             signature as the authorization/replay identity. ECDSA can admit equivalent \
             representations unless the implementation enforces a lower-half-order s value and a \
             single intended recovery-parity convention. When multiple encodings such as compact \
             and traditional signatures are accepted, replay/uniqueness state must be keyed by the \
             authenticated message, nonce, or authorization identifier rather than raw signature \
             bytes. Use a reviewed canonical recovery implementation, reject high-s values, validate \
             v/parity strictly, normalize accepted encodings before security-sensitive identity \
             decisions, and never rely on keccak256(signature) or equivalent raw serialization as a \
             unique authorization key.",
        )
    }

    fn instances(&self) -> BTreeMap<(String, usize, String), NodeID> {
        self.found_instances.clone()
    }

    fn name(&self) -> String {
        format!("{}", IssueDetectorNamePool::SignatureMalleability)
    }
}

fn build_models(context: &WorkspaceContext) -> BTreeMap<NodeID, FunctionModel> {
    let function_spans: Vec<(NodeID, SrcSpan)> = context
        .function_definitions()
        .into_iter()
        .filter_map(|f| SrcSpan::parse(&f.src).map(|span| (f.id, span)))
        .collect();
    let function_ids: HashSet<NodeID> = function_spans.iter().map(|(id, _)| *id).collect();

    let span_by_id: HashMap<NodeID, SrcSpan> = function_spans.iter().copied().collect();
    let mut functions_by_name: HashMap<String, Vec<NodeID>> = HashMap::new();
    let mut functions_by_file_and_name: HashMap<(usize, String), Vec<NodeID>> = HashMap::new();
    let mut source_by_id: HashMap<NodeID, String> = HashMap::new();
    for function in context.function_definitions() {
        let source = function.peek(context).unwrap_or_default();
        if let Some(name) = function_name(&source) {
            functions_by_name.entry(name.clone()).or_default().push(function.id);
            if let Some(span) = span_by_id.get(&function.id) {
                functions_by_file_and_name
                    .entry((span.file, name))
                    .or_default()
                    .push(function.id);
            }
        }
        source_by_id.insert(function.id, source);
    }

    let mut direct_ecrecover_positions: HashMap<NodeID, Vec<usize>> = HashMap::new();
    for identifier in context.identifiers() {
        if identifier.name != "ecrecover" {
            continue;
        }
        let Some(node_span) = SrcSpan::parse(&identifier.src) else {
            continue;
        };
        let Some((function_id, function_span)) = enclosing_function(node_span, &function_spans)
        else {
            continue;
        };
        direct_ecrecover_positions
            .entry(function_id)
            .or_default()
            .push(node_span.start.saturating_sub(function_span.start));
    }

    let mut calls_by_function: HashMap<NodeID, Vec<CallSite>> = HashMap::new();
    let mut unresolved_crypto_members: HashMap<NodeID, Vec<(String, Vec<String>)>> = HashMap::new();

    // Internal/free-function calls.
    for identifier in context.identifiers() {
        let Some(callee) = identifier.referenced_declaration else {
            continue;
        };
        if !function_ids.contains(&callee) {
            continue;
        }
        let Some(node_span) = SrcSpan::parse(&identifier.src) else {
            continue;
        };
        let Some((caller, function_span)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        if caller == callee {
            continue;
        }
        let Some(source) = source_by_id.get(&caller) else {
            continue;
        };
        let local_pos = node_span.start.saturating_sub(function_span.start);
        let args = parse_call_args_at(source, local_pos).unwrap_or_default();
        push_call_unique(&mut calls_by_function, caller, CallSite { callee, args });
    }

    // Library/contract member calls. Aderyn's v0.6.8 WorkspaceContext accessor is intentionally
    // spelled `member_accesss()` (three s characters).
    for member in context.member_accesss() {
        let Some(node_span) = SrcSpan::parse(&member.src) else {
            continue;
        };
        let Some((caller, function_span)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        let Some(source) = source_by_id.get(&caller) else {
            continue;
        };
        let local_pos = node_span.start.saturating_sub(function_span.start);
        let args = parse_call_args_at(source, local_pos).unwrap_or_default();

        // Resolve member calls without depending on a version-sensitive MemberAccess accessor.
        // Prefer a same-source-file function with the member name (typical external verifier/mock),
        // then fall back to a globally unique function name (typical imported library helper).
        // If either lookup is ambiguous, do not guess.
        let same_file_key = (node_span.file, member.member_name.clone());
        if let Some(ids) = functions_by_file_and_name.get(&same_file_key) {
            if ids.len() == 1 && ids[0] != caller {
                push_call_unique(
                    &mut calls_by_function,
                    caller,
                    CallSite {
                        callee: ids[0],
                        args: args.clone(),
                    },
                );
                continue;
            }
        }
        if let Some(ids) = functions_by_name.get(&member.member_name) {
            if ids.len() == 1 && ids[0] != caller {
                push_call_unique(
                    &mut calls_by_function,
                    caller,
                    CallSite {
                        callee: ids[0],
                        args: args.clone(),
                    },
                );
                continue;
            }
        }

        if matches!(member.member_name.as_str(), "recover" | "tryRecover") {
            unresolved_crypto_members
                .entry(caller)
                .or_default()
                .push((member.member_name.clone(), args));
        }
    }

    let mut models = BTreeMap::new();
    for function in context.function_definitions() {
        let source = source_by_id.remove(&function.id).unwrap_or_default();
        let assignments = collect_assignments(&source);
        let ecrecover_positions = direct_ecrecover_positions
            .remove(&function.id)
            .unwrap_or_default();
        let direct_raw = analyze_direct_ecrecover(&source, &assignments, &ecrecover_positions);
        let unresolved = unresolved_crypto_members
            .remove(&function.id)
            .unwrap_or_default();

        let unresolved_recover = !unresolved.is_empty();
        let unresolved_bytes_recover = unresolved.iter().any(|(_, args)| {
            args.len() >= 2
                && parse_dynamic_bytes_parameter_names(&source)
                    .iter()
                    .any(|p| identifiers_in_text(&args[args.len() - 1]).contains(p))
        });

        let exact_signature_lengths = collect_exact_signature_lengths(&source);
        let direct_flexible = has_local_flexible_encoding(&source)
            || exact_signature_lengths.len() >= 2
            || unresolved_bytes_recover;

        let direct = CryptoSummary {
            signature_verification: !ecrecover_positions.is_empty() || unresolved_recover,
            unsafe_high_s: direct_raw.unsafe_high_s,
            permissive_v: direct_raw.permissive_v,
            flexible_encoding: direct_flexible,
        };

        models.insert(
            function.id,
            FunctionModel {
                id: function.id,
                scope: function.scope,
                source: source.clone(),
                entry_point: is_public_or_external(&source),
                direct,
                calls: calls_by_function.remove(&function.id).unwrap_or_default(),
                exact_signature_lengths,
                signature_components: direct_raw.signature_components,
            },
        );
    }

    models
}

fn push_call_unique(
    calls_by_function: &mut HashMap<NodeID, Vec<CallSite>>,
    caller: NodeID,
    call: CallSite,
) {
    let calls = calls_by_function.entry(caller).or_default();
    let duplicate = calls
        .iter()
        .any(|existing| existing.callee == call.callee && existing.args == call.args);
    if !duplicate {
        calls.push(call);
    }
}

fn enclosing_function(node: SrcSpan, functions: &[(NodeID, SrcSpan)]) -> Option<(NodeID, SrcSpan)> {
    functions
        .iter()
        .filter(|(_, span)| span.contains(node))
        .min_by_key(|(_, span)| span.len)
        .copied()
}

#[derive(Debug, Default)]
struct RawRecoveryAnalysis {
    unsafe_high_s: bool,
    permissive_v: bool,
    signature_components: BTreeSet<String>,
}

fn analyze_direct_ecrecover(
    source: &str,
    assignments: &HashMap<String, String>,
    positions: &[usize],
) -> RawRecoveryAnalysis {
    let mut out = RawRecoveryAnalysis::default();
    let mut v_expressions = Vec::new();

    for pos in positions {
        let Some(args) = parse_call_args_at(source, *pos) else {
            continue;
        };
        if args.len() < 4 {
            continue;
        }
        let v = args[1].trim().to_string();
        let r = args[2].trim().to_string();
        let s = args[3].trim().to_string();
        v_expressions.push(v.clone());

        out.signature_components.extend(identifiers_in_text(&v));
        out.signature_components.extend(identifiers_in_text(&r));
        out.signature_components.extend(identifiers_in_text(&s));

        let before = source.get(..*pos).unwrap_or(source);
        if !has_effective_low_s_guard(before, &s, assignments) {
            out.unsafe_high_s = true;
        }
        if v_expression_is_permissive(source, before, &v, assignments) {
            out.permissive_v = true;
        }
    }

    // Fallback convention: one recovery tries the supplied v and another tries v + 27. This accepts
    // both 0/1 and 27/28 representations even if each individual call looks ordinary.
    for a in &v_expressions {
        for b in &v_expressions {
            let ac = compact(a);
            let bc = compact(b);
            if ac == bc {
                continue;
            }
            if compact(&format!("({a})+27")) == bc
                || compact(&format!("{a}+27")) == bc
                || compact(&format!("({b})+27")) == ac
                || compact(&format!("{b}+27")) == ac
            {
                out.permissive_v = true;
            }
        }
    }

    out
}

fn has_effective_low_s_guard(
    source_before_sink: &str,
    s_expression: &str,
    assignments: &HashMap<String, String>,
) -> bool {
    let expanded = expand_expression(s_expression, assignments, 6);
    let mut candidates = identifiers_in_text(&expanded);
    candidates.extend(identifiers_in_text(s_expression));
    if candidates.is_empty() {
        return false;
    }

    for statement in split_statements(source_before_sink) {
        let statement_compact = compact(&statement);
        for symbol in &candidates {
            for needle in [symbol.clone(), format!("uint256({symbol})")] {
                if upper_bound_is_canonical(&statement_compact, &needle, assignments) {
                    return true;
                }
                if rejecting_high_s_branch(&statement_compact, &needle, assignments) {
                    return true;
                }
            }
        }
    }
    false
}

fn upper_bound_is_canonical(
    statement: &str,
    needle: &str,
    assignments: &HashMap<String, String>,
) -> bool {
    let mut search_from = 0usize;
    while let Some(rel) = statement[search_from..].find(needle) {
        let pos = search_from + rel + needle.len();
        let tail = &statement[pos..];
        let (op, rest) = if let Some(rest) = tail.strip_prefix("<=") {
            ("<=", rest)
        } else if let Some(rest) = tail.strip_prefix('<') {
            ("<", rest)
        } else {
            search_from = pos;
            if search_from >= statement.len() {
                break;
            }
            continue;
        };
        let bound = take_expression_atom(rest);
        if bound_is_lower_half_order(&bound, op == "<", assignments) {
            return true;
        }
        search_from = pos;
        if search_from >= statement.len() {
            break;
        }
    }
    false
}

fn rejecting_high_s_branch(
    statement: &str,
    needle: &str,
    assignments: &HashMap<String, String>,
) -> bool {
    if !(statement.contains("return") || statement.contains("revert")) {
        return false;
    }
    let mut search_from = 0usize;
    while let Some(rel) = statement[search_from..].find(needle) {
        let pos = search_from + rel + needle.len();
        let tail = &statement[pos..];
        let rest = if let Some(rest) = tail.strip_prefix('>') {
            rest.strip_prefix('=').unwrap_or(rest)
        } else {
            search_from = pos;
            if search_from >= statement.len() {
                break;
            }
            continue;
        };
        let bound = take_expression_atom(rest);
        if bound_is_lower_half_order(&bound, false, assignments) {
            return true;
        }
        search_from = pos;
        if search_from >= statement.len() {
            break;
        }
    }
    false
}

fn take_expression_atom(text: &str) -> String {
    let text = text.trim_start();
    if text.starts_with('(') {
        if let Some(close) = matching_delimiter(text, 0, '(', ')') {
            return text[..=close].to_string();
        }
    }
    let end = text
        .find(|c: char| matches!(c, '&' | '|' | ',' | ';' | ')' | '{' | '}'))
        .unwrap_or(text.len());
    text[..end].trim().trim_matches('(').trim_matches(')').to_string()
}

fn bound_is_lower_half_order(
    raw_bound: &str,
    strict_less: bool,
    assignments: &HashMap<String, String>,
) -> bool {
    let mut bound = raw_bound.trim().trim_matches('(').trim_matches(')').to_string();
    if let Some(expanded) = single_identifier(&bound).and_then(|id| assignments.get(&id)) {
        bound = expanded.trim().trim_matches('(').trim_matches(')').to_string();
    }
    let compacted = compact(&bound).to_ascii_lowercase();

    // secp256k1 n / 2, as used by EIP-2/OpenZeppelin canonical-s checks.
    const HALF_N_HEX: &str =
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
    const HALF_N_PLUS_ONE_HEX: &str =
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1";
    const HALF_N_DEC: &str =
        "57896044618658097711785492504343953926418782139537452191302581570759080747168";
    const HALF_N_PLUS_ONE_DEC: &str =
        "57896044618658097711785492504343953926418782139537452191302581570759080747169";

    if let Some(hex) = compacted.strip_prefix("0x") {
        let normalized = hex.trim_start_matches('0');
        let threshold = if strict_less {
            HALF_N_PLUS_ONE_HEX
        } else {
            HALF_N_HEX
        };
        return numeric_string_leq(normalized, threshold);
    }
    if compacted.chars().all(|c| c.is_ascii_digit()) && !compacted.is_empty() {
        let normalized = compacted.trim_start_matches('0');
        let threshold = if strict_less {
            HALF_N_PLUS_ONE_DEC
        } else {
            HALF_N_DEC
        };
        return numeric_string_leq(normalized, threshold);
    }

    // If the bound resolves to a symbolic constant that is not visible inside the function source,
    // retain the explicit upper-bound evidence rather than reverting to the old "every ecrecover is
    // vulnerable" behavior. Literal bounds are validated exactly above, so full-order constants such
    // as secp256k1 n are still rejected when their value is available locally.
    single_identifier(&compacted).is_some()
}

fn numeric_string_leq(value: &str, threshold: &str) -> bool {
    let value = if value.is_empty() { "0" } else { value };
    let threshold = threshold.trim_start_matches('0');
    value.len() < threshold.len() || (value.len() == threshold.len() && value <= threshold)
}

fn single_identifier(text: &str) -> Option<String> {
    let ids = identifiers_in_text(text);
    if ids.len() == 1 {
        ids.into_iter().next()
    } else {
        None
    }
}

fn v_expression_is_permissive(
    full_source: &str,
    source_before_sink: &str,
    v_expression: &str,
    assignments: &HashMap<String, String>,
) -> bool {
    let expanded = compact(&expand_expression(v_expression, assignments, 8));
    let direct = compact(v_expression);

    // Lossy transformations of recovery parity.
    if expanded.contains('%')
        || expanded.contains("&1")
        || expanded.contains("&0x1")
        || expanded.contains("?27:28")
        || expanded.contains("?28:27")
    {
        return true;
    }

    let ids = identifiers_in_text(v_expression);
    for id in ids {
        let compact_before = compact(source_before_sink);
        let compact_full = compact(full_source);

        if compact_before.contains(&format!("if({id}<27)"))
            && (compact_before.contains(&format!("{id}+=27"))
                || compact_before.contains(&format!("{id}={id}+27")))
        {
            return true;
        }
        if compact_before.contains(&format!("if({id}<=1)"))
            && (compact_before.contains(&format!("{id}+=27"))
                || compact_before.contains(&format!("{id}={id}+27")))
        {
            return true;
        }
        if compact_before.contains(&format!("if({id}>=35)"))
            || compact_before.contains(&format!("if({id}>34)"))
        {
            return true;
        }
        if compact_before.contains(&format!("{id}={id}==0?27:28"))
            || compact_before.contains(&format!("{id}=({id}==0)?27:28"))
        {
            return true;
        }

        let plus_27 = direct == compact(&format!("{id}+27"))
            || direct == compact(&format!("({id})+27"));
        if plus_27 {
            // A dedicated parity-0/1 API is safe if it rejects values outside 0/1 before recovery.
            if has_strict_parity_precondition(source_before_sink, &id)
                && !has_direct_ecrecover_with_v(full_source, &id)
            {
                continue;
            }
            return true;
        }

        if let Some(rhs) = assignments.get(&id) {
            let rhs = compact(&expand_expression(rhs, assignments, 6));
            if rhs.contains('%')
                || rhs.contains("&1")
                || rhs.contains("&0x1")
                || rhs.contains("?27:28")
                || rhs.contains("?28:27")
            {
                return true;
            }
        }

        // A two-convention fallback often performs raw recovery with the supplied v first and then
        // retries with v+27 for 0/1 values.
        if compact_full.contains("ecrecover(")
            && compact_full.contains(&format!("{id}+27"))
            && has_direct_ecrecover_with_v(full_source, &id)
        {
            return true;
        }
    }

    false
}

fn has_strict_parity_precondition(source_before_sink: &str, symbol: &str) -> bool {
    let compacted = compact(source_before_sink);
    compacted.contains(&format!("require({symbol}<=1"))
        || compacted.contains(&format!("require({symbol}<2"))
        || compacted.contains(&format!("assert({symbol}<=1"))
        || compacted.contains(&format!("assert({symbol}<2"))
        || (compacted.contains(&format!("if({symbol}>1)"))
            && (compacted.contains("revert") || compacted.contains("return")))
        || (compacted.contains(&format!("if({symbol}>=2)"))
            && (compacted.contains("revert") || compacted.contains("return")))
}

fn has_direct_ecrecover_with_v(source: &str, symbol: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = find_word_from(source, "ecrecover", from) {
        if let Some(args) = parse_call_args_at(source, pos) {
            if args.len() >= 4 && compact(&args[1]) == compact(symbol) {
                return true;
            }
        }
        from = pos + "ecrecover".len();
        if from >= source.len() {
            break;
        }
    }
    false
}

fn propagate_crypto_summaries(
    models: &BTreeMap<NodeID, FunctionModel>,
) -> HashMap<NodeID, CryptoSummary> {
    let mut summaries: HashMap<NodeID, CryptoSummary> = models
        .values()
        .map(|model| (model.id, model.direct.clone()))
        .collect();

    for _ in 0..12 {
        let snapshot = summaries.clone();
        let mut changed = false;
        for model in models.values() {
            let Some(summary) = summaries.get_mut(&model.id) else {
                continue;
            };
            for call in &model.calls {
                if let Some(callee) = snapshot.get(&call.callee) {
                    changed |= summary.merge_from(callee);
                }
            }
        }
        if !changed {
            break;
        }
    }
    summaries
}

fn path_is_proven_canonical(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    summaries: &HashMap<NodeID, CryptoSummary>,
    visited: &mut BTreeSet<NodeID>,
    depth: usize,
) -> bool {
    if depth == 0 || !visited.insert(id) {
        return false;
    }
    let Some(summary) = summaries.get(&id) else {
        return false;
    };
    if summary.unsafe_high_s || summary.permissive_v {
        return false;
    }
    let Some(model) = models.get(&id) else {
        return false;
    };
    if model.direct.signature_verification {
        // A direct unresolved recover/tryRecover is treated as reviewed/canonical unless other local
        // evidence shows a permissive/high-s path. Raw ecrecover safety is already established by the
        // direct summary.
        return true;
    }
    model.calls.iter().any(|call| {
        summaries
            .get(&call.callee)
            .is_some_and(|s| s.signature_verification)
            && path_is_proven_canonical(call.callee, models, summaries, visited, depth - 1)
    })
}

fn uses_signature_serialization_as_security_identity(
    model: &FunctionModel,
    summary: &CryptoSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
    summaries: &HashMap<NodeID, CryptoSummary>,
) -> bool {
    if !summary.signature_verification {
        return false;
    }

    let assignments = collect_assignments(&model.source);
    let dynamic_bytes: BTreeSet<String> = parse_dynamic_bytes_parameter_names(&model.source)
        .into_iter()
        .collect();
    let mut signature_symbols = model.signature_components.clone();

    // Signature arguments passed into a verifier/helper become signature data at the caller. We use
    // referenced declarations and the callee summary, not parameter names.
    for call in &model.calls {
        let Some(callee_summary) = summaries.get(&call.callee) else {
            continue;
        };
        if !callee_summary.signature_verification {
            continue;
        }
        if call.args.len() >= 4 {
            for arg in call.args.iter().rev().take(3) {
                signature_symbols.extend(identifiers_in_text(arg));
            }
        }
        for arg in &call.args {
            for symbol in identifiers_in_text(arg) {
                if dynamic_bytes.contains(&symbol) {
                    signature_symbols.insert(symbol);
                }
            }
        }
    }

    // If the function is signature-gated through an unresolved reviewed library call, a dynamic
    // bytes parameter supplied to that call is still a signature serialization candidate.
    if signature_symbols.is_empty() && summary.signature_verification {
        signature_symbols.extend(dynamic_bytes.iter().cloned());
    }

    // Tuple extraction from a dynamic signature, e.g. `(r,s,v) = split(signature)`, is deliberately
    // handled by recognizing hash expressions that either depend on the dynamic bytes itself or on at
    // least two ECDSA component symbols used by recovery.
    let mut derived_keys = BTreeSet::new();
    for (lhs, rhs) in &assignments {
        if !is_hash_expression(rhs) {
            continue;
        }
        let expanded = expand_expression(rhs, &assignments, 6);
        let deps = identifiers_in_text(&expanded);
        let direct_dynamic = deps.iter().any(|d| dynamic_bytes.contains(d));
        let component_hits = deps
            .iter()
            .filter(|d| signature_symbols.contains(*d))
            .count();
        if direct_dynamic || component_hits >= 2 {
            derived_keys.insert(lhs.clone());
        }
    }

    // Direct hash expressions inside an indexed state access are also security identity candidates.
    if indexed_security_use_of_direct_signature_hash(
        &model.source,
        &dynamic_bytes,
        &signature_symbols,
        &assignments,
    ) {
        return true;
    }

    derived_keys
        .iter()
        .any(|key| indexed_security_use_of_key(&model.source, key))
        || callee_contains_serialization_identity(model, models, summaries)
}

fn callee_contains_serialization_identity(
    model: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    summaries: &HashMap<NodeID, CryptoSummary>,
) -> bool {
    model.calls.iter().any(|call| {
        let Some(callee) = models.get(&call.callee) else {
            return false;
        };
        let Some(summary) = summaries.get(&call.callee) else {
            return false;
        };
        if !summary.signature_verification {
            return false;
        }
        let assignments = collect_assignments(&callee.source);
        let dynamic_bytes: BTreeSet<String> = parse_dynamic_bytes_parameter_names(&callee.source)
            .into_iter()
            .collect();
        assignments.iter().any(|(lhs, rhs)| {
            is_hash_expression(rhs)
                && identifiers_in_text(rhs)
                    .iter()
                    .any(|d| dynamic_bytes.contains(d))
                && indexed_security_use_of_key(&callee.source, lhs)
        })
    })
}

fn is_hash_expression(expression: &str) -> bool {
    let compacted = compact(expression);
    compacted.contains("keccak256(")
        || compacted.contains("sha256(")
        || compacted.contains("ripemd160(")
}

fn indexed_security_use_of_key(source: &str, key: &str) -> bool {
    let compacted = compact(source);
    let bracket = format!("[{key}]");
    let occurrences = compacted.matches(&bracket).count();
    if occurrences == 0 {
        return false;
    }

    // A single telemetry write such as `lastHash = key` is not indexed and therefore never reaches
    // this branch. A mapping/array access keyed by the serialized signature is security-sensitive if
    // it participates in a guard, or if the same indexed key is used more than once (typically a
    // read/check plus a consuming write).
    let guarded = split_statements(source).into_iter().any(|statement| {
        let statement = compact(&statement);
        statement.contains(&bracket)
            && (statement.contains("require(")
                || statement.contains("assert(")
                || statement.contains("if("))
    });
    guarded || occurrences >= 2
}

fn indexed_security_use_of_direct_signature_hash(
    source: &str,
    dynamic_bytes: &BTreeSet<String>,
    signature_components: &BTreeSet<String>,
    assignments: &HashMap<String, String>,
) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'[' {
            i += 1;
            continue;
        }
        let Some(close) = matching_delimiter(source, i, '[', ']') else {
            break;
        };
        let expr = &source[i + 1..close];
        if is_hash_expression(expr) {
            let expanded = expand_expression(expr, assignments, 6);
            let deps = identifiers_in_text(&expanded);
            let dynamic = deps.iter().any(|d| dynamic_bytes.contains(d));
            let components = deps
                .iter()
                .filter(|d| signature_components.contains(*d))
                .count();
            if dynamic || components >= 2 {
                return true;
            }
        }
        i = close + 1;
    }
    false
}

fn collect_exact_signature_lengths(source: &str) -> BTreeSet<u64> {
    let params = parse_dynamic_bytes_parameter_names(source);
    let compacted = compact(source);
    let mut lengths = BTreeSet::new();
    for param in params {
        let needle = format!("{param}.length==");
        let mut from = 0usize;
        while let Some(rel) = compacted[from..].find(&needle) {
            let pos = from + rel + needle.len();
            if let Some(value) = parse_decimal_prefix(&compacted[pos..]) {
                lengths.insert(value);
            }
            from = pos;
            if from >= compacted.len() {
                break;
            }
        }
        // Also support reversed equality, e.g. `65 == signature.length`.
        for value in [64u64, 65, 66, 96] {
            if compacted.contains(&format!("{value}=={param}.length")) {
                lengths.insert(value);
            }
        }
    }
    lengths
}

fn has_local_flexible_encoding(source: &str) -> bool {
    let params = parse_dynamic_bytes_parameter_names(source);
    let compacted = compact(source);
    for param in params {
        if compacted.contains(&format!("{param}.length>="))
            || compacted.contains(&format!("{param}.length>65"))
            || compacted.contains(&format!("abi.decode({param},(bytes))"))
            || compacted.contains(&format!("abi.decode({param},(bytesmemory))"))
        {
            return true;
        }
        let lengths = collect_exact_signature_lengths(source);
        if lengths.len() >= 2 {
            return true;
        }
    }
    false
}

fn parse_decimal_prefix(text: &str) -> Option<u64> {
    let digits: String = text.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_half_order_literal() {
        let source = r#"
            require(uint256(sigS) > 0 && uint256(sigS) <=
                0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,
                "high s");
        "#;
        assert!(has_effective_low_s_guard(
            source,
            "sigS",
            &HashMap::new()
        ));
    }

    #[test]
    fn rejects_full_curve_order_as_low_s_guard() {
        let source = r#"
            require(uint256(sigS) <
                0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
                "range");
        "#;
        assert!(!has_effective_low_s_guard(
            source,
            "sigS",
            &HashMap::new()
        ));
    }

    #[test]
    fn strict_parity_zero_one_then_plus_27_is_safe() {
        let source = r#"
            require(parity <= 1, "parity");
            require(ecrecover(digest, parity + 27, r, s) == signer, "bad");
        "#;
        assert!(!v_expression_is_permissive(
            source,
            source,
            "parity + 27",
            &HashMap::new()
        ));
    }

    #[test]
    fn add_27_normalization_is_permissive() {
        let source = r#"
            if (recovery < 27) recovery += 27;
            require(ecrecover(digest, recovery, r, s) == signer, "bad");
        "#;
        assert!(v_expression_is_permissive(
            source,
            source,
            "recovery",
            &HashMap::new()
        ));
    }

    #[test]
    fn modulo_normalization_is_permissive() {
        let mut assignments = HashMap::new();
        assignments.insert("effective".to_string(), "uint8((uint256(inputV) % 27) + 27)".to_string());
        assert!(v_expression_is_permissive(
            "",
            "",
            "effective",
            &assignments
        ));
    }

    #[test]
    fn detects_multiple_signature_lengths() {
        let source = r#"
            function verify(bytes calldata sig) external {
                require(sig.length == 64 || sig.length == 65, "length");
            }
        "#;
        let lengths = collect_exact_signature_lengths(source);
        assert!(lengths.contains(&64));
        assert!(lengths.contains(&65));
        assert!(has_local_flexible_encoding(source));
    }

    #[test]
    fn telemetry_hash_is_not_security_identity() {
        let source = r#"
            function run(bytes calldata sig) external {
                bytes32 observation = keccak256(sig);
                lastObserved = observation;
            }
        "#;
        assert!(!indexed_security_use_of_key(source, "observation"));
    }

    #[test]
    fn mapping_guard_and_write_is_security_identity() {
        let source = r#"
            function run(bytes calldata sig) external {
                bytes32 key = keccak256(sig);
                require(!seen[key], "used");
                seen[key] = true;
            }
        "#;
        assert!(indexed_security_use_of_key(source, "key"));
    }
}
