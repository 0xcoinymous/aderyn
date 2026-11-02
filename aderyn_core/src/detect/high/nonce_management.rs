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
    collect_assignments, compact, contains_word, expand_expression, find_top_level_operator,
    function_name, identifier_sequence, identifiers_in_text, is_public_or_external,
    matching_delimiter, operand_before, parse_call_args_at, recovered_into_variable, returned_expressions,
    split_statements, split_top_level, substitute_identifiers, SrcSpan,
};

/// Detects application-level authorization nonce defects on signature-gated Solidity paths.
///
/// This detector does NOT concern the off-chain ECDSA ephemeral signing nonce `k`. It models
/// persistent authorization state used by the contract: sequential counters, monotonic sequences,
/// random authorization identifiers, unordered nonce bitmaps, nonce namespaces, cancellation and
/// invalidation state, salts/epochs used as authorization versions, and rollback-sensitive nonce
/// consumption.
///
/// Aderyn v0.6.8 does not expose an SSA/CFG framework to detectors, so the implementation combines
/// AST discovery (functions, identifiers/member accesses, referenced declarations) with a bounded,
/// Solidity-aware source/data-flow layer. Classification is based on authenticated data, storage
/// guards and storage writes; names such as "nonce" or "sequence" are only weak semantic hints and
/// never sufficient by themselves to emit a finding.
#[derive(Default)]
pub struct NonceManagementDetector {
    found_instances: BTreeMap<(String, usize, String), NodeID>,
}

#[derive(Debug, Clone)]
struct CallSite {
    callee: NodeID,
    name: String,
    args: Vec<String>,
    pos: usize,
    principal_after_call: Option<String>,
    /// The variable that receives the result, e.g. `signer` in `address signer = recoverSigner(..)`.
    recovered_into: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AuthSummary {
    signature_verification: bool,
    signature_count: usize,
    authenticated_roots: BTreeSet<String>,
    principal_roots: BTreeSet<String>,
    /// The digest each recovery verifies, in the function's own terms.
    digests: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct Parameter {
    raw: String,
    name: String,
}

#[derive(Debug, Clone)]
struct FunctionModel {
    id: NodeID,
    scope: NodeID,
    source: String,
    entry_point: bool,
    parameters: Vec<Parameter>,
    assignments: HashMap<String, String>,
    calls: Vec<CallSite>,
    direct_auth: AuthSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct StateSlot {
    base: String,
    keys: Vec<String>,
    field: Option<String>,
}

/// Whitespace removed, except one space between two words, so that `new bytes(..)` stays two identifiers.
fn compact_key(text: &str) -> String {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            gap = true;
            continue;
        }
        if gap && word(ch) && out.chars().last().is_some_and(word) {
            out.push(' ');
        }
        gap = false;
        out.push(ch);
    }
    out
}

impl StateSlot {
    fn normalized(&self, assignments: &HashMap<String, String>) -> Self {
        Self {
            base: self.base.clone(),
            keys: self
                .keys
                .iter()
                .map(|key| compact_key(&expand_expression(key, assignments, 4)))
                .collect(),
            field: self.field.clone(),
        }
    }

    fn same_storage_location(&self, other: &Self) -> bool {
        self.base == other.base && self.field == other.field && self.keys == other.keys
    }

    fn same_storage_family(&self, other: &Self) -> bool {
        self.base == other.base && self.field == other.field
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardKind {
    Equality,
    MonotonicGreater,
    BoolClear,
    BitmapClear,
    PresenceOnly,
}

#[derive(Debug, Clone)]
struct GuardFact {
    slot: StateSlot,
    kind: GuardKind,
    candidate: String,
    mask: Option<String>,
    pos: usize,
    bypassable: bool,
    lossy: bool,
    authenticated: bool,
    /// `require(nonce == nonces[signer] + 1)`: the checked value is one past the stored one, so storing
    /// it advances the slot.
    ahead: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteKind {
    Assign,
    AddAssign,
    SubAssign,
    OrAssign,
    XorAssign,
    AndAssign,
    Increment,
    Decrement,
    Delete,
}

#[derive(Debug, Clone)]
struct WriteFact {
    slot: StateSlot,
    kind: WriteKind,
    rhs: String,
    pos: usize,
    conditional: bool,
}

#[derive(Debug, Clone, Default)]
struct StateHelperSummary {
    returned_slot: Option<StateSlot>,
    guards: Vec<GuardFact>,
    writes: Vec<WriteFact>,
}

#[derive(Debug, Clone, Default)]
struct NonceAssessment {
    nonce_activity: bool,
    suspicious: bool,
    rollback_sensitive: bool,
    guarded_slots: Vec<StateSlot>,
    /// Guarded slots that this function itself consumes (writes after checking, or advances in the digest).
    consumed_slots: Vec<StateSlot>,
    /// Guarded slots checked to be unused (zero/false) before use: only clearing them revives a signature.
    cleared_slots: Vec<StateSlot>,
}

impl IssueDetector for NonceManagementDetector {
    fn detect(&mut self, context: &WorkspaceContext) -> Result<bool, Box<dyn Error>> {
        let models = build_models(context);
        if models.is_empty() {
            return Ok(false);
        }

        let auth_summaries = propagate_auth_summaries(&models);
        let helper_summaries = build_state_helper_summaries(&models);

        let mut assessments: BTreeMap<NodeID, NonceAssessment> = BTreeMap::new();
        for model in models.values() {
            if !model.entry_point {
                continue;
            }
            let auth = auth_summaries.get(&model.id).cloned().unwrap_or_default();
            if !auth.signature_verification || !can_change_state(model) || self_call_only(model, &models) {
                continue;
            }
            assessments.insert(
                model.id,
                assess_entry_function(model, &auth, &models, &helper_summaries),
            );
        }

        // Class 4 also requires contract-level reasoning: a perfectly correct signed entry point can
        // still be unsafe if another externally reachable function can reset/decrease/clear the same
        // authorization state. This pass is based on storage families and mutation semantics, not on
        // benchmark-specific names.
        let mut vulnerable = BTreeSet::new();
        for model in models.values().filter(|m| m.entry_point) {
            let Some(assessment) = assessments.get(&model.id) else {
                continue;
            };
            if !assessment.nonce_activity {
                continue;
            }

            if assessment.suspicious || assessment.rollback_sensitive {
                vulnerable.insert(model.id);
                continue;
            }

            if has_dangerous_cross_function_mutation(
                model,
                assessment,
                &models,
                &auth_summaries,
                &helper_summaries,
            ) {
                vulnerable.insert(model.id);
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
        IssueSeverity::High
    }

    fn title(&self) -> String {
        String::from("Signature Authorization Nonce Management Vulnerability")
    }

    fn description(&self) -> String {
        String::from(
            "A signature-authorized operation uses persistent nonce, sequence, authorization, bitmap, cancellation, or equivalent one-time state incorrectly. The authorization value may be omitted from the signed digest, compared against the wrong or transient state, checked but not consumed, consumed in a different signer/namespace slot, made reversible by reset/decrease/bitmap-clearing logic, or rolled back by a later revert. Bind the authorization nonce and its namespace to the signed message, compare it against the intended persistent state, and irreversibly advance/consume the exact same storage slot. For unordered nonces, reject already-dirty bits before or atomically with setting them. Invalidation must be monotonic or one-way, and failure handling must not restore consumed authorization state unless replay is intentionally permitted.",
        )
    }

    fn instances(&self) -> BTreeMap<(String, usize, String), NodeID> {
        self.found_instances.clone()
    }

    fn name(&self) -> String {
        format!("{}", IssueDetectorNamePool::NonceManagement)
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

    let mut source_by_id = HashMap::new();
    let mut functions_by_name: HashMap<String, Vec<NodeID>> = HashMap::new();
    let mut functions_by_file_and_name: HashMap<(usize, String), Vec<NodeID>> = HashMap::new();
    for function in context.function_definitions() {
        let source = super::signature_utils::blank_comments(&function.peek(context).unwrap_or_default());
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
    let mut unresolved_signature_members: HashMap<NodeID, Vec<(String, Vec<String>, usize)>> =
        HashMap::new();

    // Important Aderyn v0.6.8 compatibility detail: referenced_declaration is a FIELD in the
    // user's checkout, not a method, and function_definitions() returns Vec and therefore needs
    // into_iter() before iterator adaptors.
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
        push_call_unique(
            &mut calls_by_function,
            caller,
            CallSite {
                callee,
                name: identifier.name.clone(),
                args,
                pos: local_pos,
                principal_after_call: principal_after_call(source, local_pos),
                        recovered_into: recovered_into_variable(source, local_pos),
            },
        );
    }

    // Aderyn v0.6.8 intentionally spells this accessor member_accesss() with three 's' characters.
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
        let (receiver, member_args) =
            super::signature_utils::member_call_parts(source, local_pos, &member.member_name)
                .unwrap_or((None, parse_call_args_at(source, local_pos).unwrap_or_default()));
        // A `using L for T` call `x.f(a)` passes `x` as the first parameter of `f`.
        let bound_args = |callee: NodeID| -> Vec<String> {
            let arity = source_by_id.get(&callee).map_or(0, |callee_source| parse_parameters(callee_source).len());
            match &receiver {
                Some(receiver) if arity == member_args.len() + 1 => {
                    std::iter::once(receiver.clone()).chain(member_args.iter().cloned()).collect()
                }
                _ => member_args.clone(),
            }
        };
        let args = member_args.clone();

        // The AST records the exact target of a library or internal member call; use it when it is
        // an implemented function, and fall back to name lookup only otherwise.
        if let Some(callee) = member.referenced_declaration.filter(|id| {
            *id != caller
                && function_ids.contains(id)
                && source_by_id.get(id).is_some_and(|callee_source| callee_source.contains('{'))
        }) {
            push_call_unique(
                &mut calls_by_function,
                caller,
                CallSite {
                    callee,
                    name: member.member_name.clone(),
                    args: bound_args(callee),
                    pos: local_pos,
                    principal_after_call: principal_after_call(source, local_pos),
                        recovered_into: recovered_into_variable(source, local_pos),
                },
            );
            continue;
        }

        let same_file_key = (node_span.file, member.member_name.clone());
        if let Some(ids) = functions_by_file_and_name.get(&same_file_key) {
            if ids.len() == 1 && ids[0] != caller {
                push_call_unique(
                    &mut calls_by_function,
                    caller,
                    CallSite {
                        callee: ids[0],
                        name: member.member_name.clone(),
                        args: bound_args(ids[0]),
                        pos: local_pos,
                        principal_after_call: principal_after_call(source, local_pos),
                        recovered_into: recovered_into_variable(source, local_pos),
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
                        name: member.member_name.clone(),
                        args: bound_args(ids[0]),
                        pos: local_pos,
                        principal_after_call: principal_after_call(source, local_pos),
                        recovered_into: recovered_into_variable(source, local_pos),
                    },
                );
                continue;
            }
        }

        if is_signature_member(&member.member_name) {
            // `hash.recover(sig)` through `using ECDSA for bytes32`: the receiver is the digest.
            let args = match &receiver {
                Some(receiver) if matches!(member.member_name.as_str(), "recover" | "tryRecover" | "recoverChecked") => {
                    std::iter::once(receiver.clone()).chain(args).collect()
                }
                _ => args,
            };
            unresolved_signature_members
                .entry(caller)
                .or_default()
                .push((member.member_name.clone(), args, local_pos));
        }
    }

    let mut models = BTreeMap::new();
    for function in context.function_definitions() {
        let source = source_by_id.remove(&function.id).unwrap_or_default();
        let assignments = collect_assignments(&source);
        let parameters = parse_parameters(&source);
        let direct_auth = analyze_direct_auth(
            &source,
            &assignments,
            &direct_ecrecover_positions
                .remove(&function.id)
                .unwrap_or_default(),
            &unresolved_signature_members
                .remove(&function.id)
                .unwrap_or_default(),
        );

        models.insert(
            function.id,
            FunctionModel {
                id: function.id,
                scope: function.scope,
                source: source.clone(),
                entry_point: is_public_or_external(&source),
                parameters,
                assignments,
                calls: calls_by_function.remove(&function.id).unwrap_or_default(),
                direct_auth,
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
    if !calls.iter().any(|existing| {
        existing.callee == call.callee && existing.pos == call.pos && existing.args == call.args
    }) {
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

fn is_signature_member(name: &str) -> bool {
    matches!(
        name,
        "recover" | "tryRecover" | "recoverChecked" | "isValid" | "isValidSignature" | "isValidSignatureNow"
    )
}

fn analyze_direct_auth(
    source: &str,
    assignments: &HashMap<String, String>,
    ecrecover_positions: &[usize],
    unresolved_members: &[(String, Vec<String>, usize)],
) -> AuthSummary {
    let mut out = AuthSummary::default();

    for pos in ecrecover_positions {
        let Some(args) = parse_call_args_at(source, *pos) else {
            continue;
        };
        if args.is_empty() {
            continue;
        }
        out.signature_verification = true;
        out.signature_count = out.signature_count.saturating_add(1).min(8);
        out.digests.insert(compact(&args[0]));
        add_authenticated_expression(&mut out, &args[0], assignments);
        if let Some(principal) = principal_after_call(source, *pos) {
            add_principal_expression(&mut out, &principal, assignments);
        }
        if let Some(recovered) = recovered_into_variable(source, *pos) {
            add_recovered_principal(&mut out, recovered);
        }
    }

    for (name, args, pos) in unresolved_members {
        if args.is_empty() {
            continue;
        }
        let (digest_index, explicit_principal_index) = match name.as_str() {
            // Common external-verifier shape: isValid(signer, digest, signature).
            "isValid" if args.len() >= 3 => (1, Some(0)),
            // OpenZeppelin SignatureChecker-style shape:
            // isValidSignatureNow(signer, digest, signature).  A two-argument member call is
            // treated like ERC-1271 and therefore uses the first argument as the digest.
            "isValidSignatureNow" if args.len() >= 3 => (1, Some(0)),
            _ => (0, None),
        };
        let Some(digest) = args.get(digest_index) else {
            continue;
        };
        out.signature_verification = true;
        out.signature_count = out.signature_count.saturating_add(1).min(8);
        out.digests.insert(compact(digest));
        add_authenticated_expression(&mut out, digest, assignments);
        if let Some(principal) = principal_after_call(source, *pos) {
            add_principal_expression(&mut out, &principal, assignments);
        } else if let Some(recovered) = recovered_into_variable(source, *pos) {
            add_recovered_principal(&mut out, recovered);
        } else if let Some(index) = explicit_principal_index {
            if let Some(principal) = args.get(index) {
                add_principal_expression(&mut out, principal, assignments);
            }
        }
    }

    out
}

fn add_authenticated_expression(
    summary: &mut AuthSummary,
    expression: &str,
    assignments: &HashMap<String, String>,
) {
    // Keep both the direct variable (e.g. digest) and its expanded dependencies. This lets a
    // digest-keyed authorizationState be recognized as authenticated while also proving that a
    // supplied nonce/namespace actually contributes to the digest.
    summary.authenticated_roots.extend(identifiers_in_text(expression));
    let expanded = expand_expression(expression, assignments, 5);
    summary.authenticated_roots.extend(identifiers_in_text(&expanded));
}

fn add_principal_expression(
    summary: &mut AuthSummary,
    expression: &str,
    assignments: &HashMap<String, String>,
) {
    let expanded = expand_expression(expression, assignments, 3);
    summary.principal_roots.extend(identifiers_in_text(&expanded));
    summary.authenticated_roots.extend(identifiers_in_text(&expanded));
}

/// The recovered signer itself, without expanding its assignment (which would add v, r, s).
fn add_recovered_principal(summary: &mut AuthSummary, name: String) {
    summary.principal_roots.insert(name.clone());
    summary.authenticated_roots.insert(name);
}

fn principal_after_call(source: &str, pos: usize) -> Option<String> {
    let tail = source.get(pos..)?;
    let open_rel = tail.find('(')?;
    let open = pos + open_rel;
    let close = matching_delimiter(source, open, '(', ')')?;
    let suffix = source.get(close + 1..)?;
    let eq = suffix.find("==")?;
    if eq > 48 {
        return None;
    }
    let after = suffix[eq + 2..].trim_start();
    let mut end = 0usize;
    for (idx, ch) in after.char_indices() {
        if matches!(ch, ',' | ';' | '&' | '|' | ')' | '}') {
            break;
        }
        end = idx + ch.len_utf8();
    }
    let expr = after[..end].trim();
    if expr.is_empty() || compact(expr).starts_with("address(0") {
        None
    } else {
        Some(expr.to_string())
    }
}

/// The number of signatures one call to `callee` verifies: at most one per signature it receives (a
/// `bytes` signature, or a `v, r, s` triple). OpenZeppelin's `ECDSA.recover(hash, sig)` has a recovery
/// for 65-byte and one for 64-byte signatures, but verifies the one signature it is given; a helper
/// that receives two signatures still counts two.
fn signatures_per_call(callee: &FunctionModel, recoveries: usize) -> usize {
    let types: Vec<String> = callee
        .parameters
        .iter()
        .map(|p| identifier_sequence(&p.raw).first().cloned().unwrap_or_default())
        .collect();
    let byte_signatures = types.iter().filter(|ty| ty.as_str() == "bytes").count();
    let triples = types.iter().filter(|ty| ty.as_str() == "uint8").count();
    let has_arrays = callee.parameters.iter().any(|p| p.raw.contains('['));
    let received = byte_signatures + triples;
    if received == 0 || has_arrays {
        recoveries
    } else {
        recoveries.min(received)
    }
}

fn propagate_auth_summaries(models: &BTreeMap<NodeID, FunctionModel>) -> BTreeMap<NodeID, AuthSummary> {
    // Each function's own digest includes what the helpers it hashes return (`_messageToRecover(..)`).
    let direct: BTreeMap<NodeID, AuthSummary> = models
        .iter()
        .map(|(id, model)| (*id, with_digest_helper_returns(model, &model.direct_auth, models)))
        .collect();
    let mut summaries = direct.clone();

    for _ in 0..6 {
        let previous = summaries.clone();
        let mut changed = false;
        for model in models.values() {
            let mut next = direct[&model.id].clone();
            let mut previous_verifier_end: Option<usize> = None;
            let mut calls: Vec<&CallSite> = model.calls.iter().collect();
            calls.sort_by_key(|call| call.pos);
            for call in calls {
                let Some(callee_model) = models.get(&call.callee) else {
                    continue;
                };
                let Some(callee) = previous.get(&call.callee) else {
                    continue;
                };
                if !callee.signature_verification {
                    continue;
                }
                next.signature_verification = true;
                // `verifyA(..) || verifyB(..)` accepts one signature in either encoding; it is one
                // authorization, not two signatures that each need their own nonce.
                let alternative = previous_verifier_end.is_some_and(|end| {
                    model.source.get(end..call.pos).is_some_and(|between| compact(between) == "||")
                });
                // One call verifies one signature: the recovery sites inside a helper such as
                // ECDSA.recover are alternative branches (65- or 64-byte signatures), not several signers.
                if !alternative {
                    next.signature_count = next
                        .signature_count
                        .saturating_add(signatures_per_call(callee_model, callee.signature_count))
                        .min(8);
                }
                previous_verifier_end = model.source.get(call.pos..).and_then(|tail| {
                    let open = call.pos + tail.find('(')?;
                    matching_delimiter(&model.source, open, '(', ')').map(|close| close + 1)
                });
                map_auth_roots_through_call(
                    &mut next.authenticated_roots,
                    &callee.authenticated_roots,
                    callee_model,
                    call,
                    &model.assignments,
                );
                let substitutions = parameter_substitutions(callee_model, call);
                next.digests.extend(
                    callee.digests.iter().map(|digest| compact(&substitute_identifiers(digest, &substitutions))),
                );
                map_auth_roots_through_call(
                    &mut next.principal_roots,
                    &callee.principal_roots,
                    callee_model,
                    call,
                    &model.assignments,
                );
                if let Some(principal) = &call.principal_after_call {
                    let expanded = expand_expression(principal, &model.assignments, 3);
                    next.principal_roots.extend(identifiers_in_text(&expanded));
                    next.authenticated_roots.extend(identifiers_in_text(&expanded));
                } else if let Some(recovered) = &call.recovered_into {
                    add_recovered_principal(&mut next, recovered.clone());
                }
            }
            if previous.get(&model.id) != Some(&next) {
                changed = true;
                summaries.insert(model.id, next);
            }
        }
        if !changed {
            break;
        }
    }

    summaries
}

fn map_auth_roots_through_call(
    destination: &mut BTreeSet<String>,
    roots: &BTreeSet<String>,
    callee: &FunctionModel,
    call: &CallSite,
    caller_assignments: &HashMap<String, String>,
) {
    let param_index: HashMap<&str, usize> = callee
        .parameters
        .iter()
        .enumerate()
        .map(|(idx, p)| (p.name.as_str(), idx))
        .collect();
    for root in roots {
        if let Some(index) = param_index.get(root.as_str()) {
            if let Some(arg) = call.args.get(*index) {
                destination.extend(identifiers_in_text(arg));
                destination.extend(identifiers_in_text(&expand_expression(
                    arg,
                    caller_assignments,
                    5,
                )));
            }
        } else {
            destination.insert(root.clone());
        }
    }
}

fn build_state_helper_summaries(
    models: &BTreeMap<NodeID, FunctionModel>,
) -> BTreeMap<NodeID, StateHelperSummary> {
    let mut out = BTreeMap::new();
    for model in models.values() {
        let locals = collect_local_names(&model.source, &model.parameters);
        let writes = collect_writes(&model.source, &model.assignments, &model.parameters, &locals);
        let returned_slot = parse_returned_slot(
            &model.source,
            &model.assignments,
            &model.parameters,
            &locals,
        );
        out.insert(
            model.id,
            StateHelperSummary {
                returned_slot,
                guards: Vec::new(),
                writes,
            },
        );
    }

    // Second pass: summarize direct storage guards in stateful helpers. Treat helper parameters as
    // provisionally authenticated here; caller instantiation recomputes authentication using the
    // actual signed roots. This supports `_consume(signer, id)` and `_expected(signer)` patterns
    // without assuming helper names.
    let base = out.clone();
    for model in models.values() {
        let locals = collect_local_names(&model.source, &model.parameters);
        let dummy = AuthSummary {
            signature_verification: true,
            signature_count: 1,
            authenticated_roots: model.parameters.iter().map(|p| p.name.clone()).collect(),
            principal_roots: BTreeSet::new(),
            digests: BTreeSet::new(),
        };
        let guards = collect_guards(model, &dummy, &locals, models, &base);
        if let Some(summary) = out.get_mut(&model.id) {
            // A write in the body of the helper's own `if (!used[k]) { used[k] = true; .. }` runs exactly
            // when the check passes, like a write after `require`.
            for write in summary.writes.iter_mut().filter(|write| write.conditional) {
                if guards.iter().any(|guard| {
                    guard.slot.same_storage_location(&write.slot)
                        && write_in_body_of_guard_if(&model.source, guard.pos, write.pos)
                }) {
                    write.conditional = false;
                }
            }
            summary.guards = guards;
        }
    }

    // The plain stores of the helpers a helper calls (`_safeMint` -> `_mint` -> `_owners[id] = to`), in
    // the helper's own terms. Counter and bitmap updates stay with the helper that checks them.
    for _ in 0..2 {
        let snapshot = out.clone();
        for model in models.values() {
            let mut nested = Vec::new();
            for call in model.calls.iter().filter(|call| call.callee != model.id) {
                let (Some(callee), Some(summary)) = (models.get(&call.callee), snapshot.get(&call.callee)) else {
                    continue;
                };
                for write in summary.writes.iter().filter(|write| write.kind == WriteKind::Assign) {
                    let mut instantiated = write.clone();
                    instantiated.slot = instantiate_slot(&write.slot, callee, call, &model.assignments);
                    instantiated.rhs = instantiate_expression(&write.rhs, callee, call, &model.assignments);
                    instantiated.pos = call.pos;
                    instantiated.conditional = write.conditional || is_inside_conditional_block(&model.source, call.pos);
                    nested.push(instantiated);
                }
            }
            if let Some(summary) = out.get_mut(&model.id) {
                summary.writes.extend(nested);
                dedup_writes(&mut summary.writes);
            }
        }
    }
    out
}

fn assess_entry_function(
    model: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
    helper_summaries: &BTreeMap<NodeID, StateHelperSummary>,
) -> NonceAssessment {
    let auth = &with_sender_binding(
        model,
        &with_equality_binding(model, &with_digest_helper_returns(model, auth, models)),
    );
    let locals = collect_local_names(&model.source, &model.parameters);
    let mut guard_locals = locals.clone();
    guard_locals.extend(memory_struct_names(&model.source));
    let mut guards = collect_guards(
        model,
        auth,
        &guard_locals,
        models,
        helper_summaries,
    );
    append_instantiated_helper_guards(model, auth, models, helper_summaries, &mut guards);
    let mut writes = collect_writes(
        &model.source,
        &model.assignments,
        &model.parameters,
        &locals,
    );
    append_instantiated_helper_writes(model, models, helper_summaries, &mut writes);

    // A Permit2-style atomic XOR can be safe without a separate pre-use guard when the returned
    // flipped word is immediately checked to prove the target bit is now set. Model this as an
    // effective bitmap invariant rather than treating every ^= as reversible.
    let xor_postcondition = has_safe_xor_postcondition(&model.source, auth, &model.assignments);

    let mut effective = 0usize;
    let mut guarded_slots = Vec::new();
    let mut cleared_slots: Vec<StateSlot> = Vec::new();
    let mut consumed_slots: Vec<StateSlot> = Vec::new();
    let mut candidate_activity = false;

    if xor_postcondition
        && writes.iter().any(|write| {
            write.kind == WriteKind::XorAssign
                && slot_keys_authenticated(&write.slot, auth, &model.assignments)
        })
    {
        effective += 1;
        candidate_activity = true;
    }

    for guard in &mut guards {
        let nonce_like = slot_has_nonce_semantic_hint(&guard.slot)
            || expression_has_nonce_semantic_hint(&guard.candidate)
            || matches!(guard.kind, GuardKind::BoolClear | GuardKind::BitmapClear);
        if nonce_like {
            candidate_activity = true;
        }
        // Only one-time state counts for the cross-function rule: a slot the function writes after
        // checking it, or a keyed nonce/used-flag slot. A checked signer, owner, pause flag or limit
        // is configuration, and changing it elsewhere does not revive a used signature.
        let written_after = writes
            .iter()
            .any(|write| write.pos >= guard.pos && write.slot.same_storage_location(&guard.slot));
        if guard.authenticated && (written_after || nonce_like && !guard.slot.keys.is_empty()) {
            guarded_slots.push(guard.slot.clone());
            if written_after {
                consumed_slots.push(guard.slot.clone());
            }
            if guard.kind == GuardKind::BoolClear {
                cleared_slots.push(guard.slot.clone());
            }
        }
        if guard.bypassable || guard.lossy || !guard.authenticated {
            continue;
        }
        if let Some(write) = writes.iter().rev().find(|write| {
            write.pos >= guard.pos && write.slot.same_storage_location(&guard.slot)
        }) {
            if write_is_effective_for_guard(guard, write, model, xor_postcondition) {
                effective += 1;
            }
        } else if guard_can_be_external_version_gate(
            guard,
            model,
            models,
            helper_summaries,
            auth,
        ) {
            // Session/epoch/version style authorization can intentionally be rotated by the signer
            // rather than consumed on every use. This prevents a simplistic "check must always be
            // followed by ++" rule from flagging valid designs.
            effective += 1;
        }
    }

    // `require(nonce == _useNonce(signer))`: a signed value compared with a helper that returns and
    // advances a counter checks and consumes that counter.
    for call in &model.calls {
        let (Some(helper), Some(callee)) = (helper_summaries.get(&call.callee), models.get(&call.callee))
        else {
            continue;
        };
        let Some(counter) = helper
            .writes
            .iter()
            .find(|write| !write.conditional && counter_write_advances(write, &callee.assignments))
        else {
            continue;
        };
        if !compared_with_signed_value(&model.source, call.pos, auth, &model.assignments) {
            continue;
        }
        let slot = instantiate_slot(&counter.slot, callee, call, &model.assignments);
        if slot_keys_authenticated(&slot, auth, &model.assignments)
            && !guarded_slots.iter().any(|guarded: &StateSlot| guarded.same_storage_location(&slot))
        {
            effective += 1;
            candidate_activity = true;
            consumed_slots.push(slot.clone());
            guarded_slots.push(slot);
        }
    }

    // A counter whose current value is in the signed digest and that is advanced unconditionally
    // (e.g. `nonces[owner]++` inside `abi.encode`, or `_useNonce(owner)`) is consumed even without
    // an explicit guard: a signature over the old value cannot verify again.
    let mut bound_slots: Vec<StateSlot> = Vec::new();
    for write in &writes {
        if write_is_digest_bound_counter(&model.source, write, &writes, auth, &model.assignments)
            && !bound_slots.iter().any(|slot| slot.same_storage_location(&write.slot))
        {
            bound_slots.push(write.slot.clone());
        }
    }
    if !bound_slots.is_empty() {
        effective += bound_slots.len();
        candidate_activity = true;
        consumed_slots.extend(bound_slots.iter().cloned());
        guarded_slots.extend(bound_slots);
    }

    if !candidate_activity {
        candidate_activity = writes.iter().any(|write| {
            write_looks_like_nonce_activity(write, auth, &model.assignments)
        });
    }

    // If the function verifies multiple independent signatures, there should normally be matching
    // independent nonce/authorization invariants unless the same authenticated digest is protected
    // by a single shared one-time key. This catches signer/co-signer namespace omissions while
    // allowing a shared digest registry to protect a single cryptographic authorization.
    let multi_signature_gap = auth.signature_count > 1
        && effective < auth.signature_count
        && !has_shared_digest_identity_guard(&guards, &writes)
        && !(effective > 0 && signatures_share_one_digest(auth, &model.assignments));

    // A `require(!flag[x])` check is a used-flag guard only when the function then sets that flag;
    // otherwise it is a configuration check such as `!isFrozen[sender]`. Without a nonce-like name, such
    // a flag is the signature's protection only when nothing else consumes the authorization (a mint's
    // token-existence check next to a signed per-caller flag is not).
    let flag_consumed = |guard: &GuardFact| {
        writes.iter().any(|write| write.pos >= guard.pos && write.slot.same_storage_location(&guard.slot))
    };
    let has_ineffective_nonce_guard = guards.iter().any(|guard| {
        (slot_has_nonce_semantic_hint(&guard.slot)
            || expression_has_nonce_semantic_hint(&guard.candidate)
            || matches!(guard.kind, GuardKind::BoolClear | GuardKind::BitmapClear)
                && flag_consumed(guard)
                && effective == 0)
            && (guard.bypassable || guard.lossy || !guard.authenticated)
    });

    let has_apparent_guard_without_effective_consumption = !guards.is_empty()
        && effective == 0
        && guards.iter().any(|guard| {
            guard.authenticated
                || slot_has_nonce_semantic_hint(&guard.slot)
                || expression_has_nonce_semantic_hint(&guard.candidate)
        });

    // A function whose only effect is a one-way mark (`cancelled[order] = true`, `nonce++`) is a
    // cancellation or invalidation: it authorises nothing that could be repeated.
    let one_way = |write: &WriteFact| match write.kind {
        WriteKind::Increment | WriteKind::AddAssign | WriteKind::OrAssign => true,
        WriteKind::Assign => {
            let rhs = compact(&write.rhs);
            // `state[id] = AuthorizationState.Canceled`: an enum member is a mark like `true`.
            let enum_member = rhs.split_once('.').is_some_and(|(ty, member)| {
                ty.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && identifier_sequence(&rhs).len() == 2
                    && !member.is_empty()
            });
            rhs == "true" || rhs == "1" || enum_member
        }
        _ => false,
    };
    let body = compact(&model.source);
    let cancellation_only = !writes.is_empty()
        && writes.iter().all(|write| one_way(write))
        && ![".call(", ".call{", "transfer(", "transferfrom(", "mint(", "send(", "approve("]
            .iter()
            .any(|effect| body.to_ascii_lowercase().contains(effect));
    let suspicious_unguarded_nonce_write = effective == 0
        && !cancellation_only
        && writes
            .iter()
            .any(|write| write_looks_like_nonce_activity(write, auth, &model.assignments));

    let rollback_sensitive = effective > 0 && has_reverting_external_flow_after_consumption(&model.source, &guards, &writes);
    let unchecked_narrow_wrap = effective > 0
        && model.source.contains("unchecked")
        && model.parameters.iter().any(|parameter| {
            is_narrow_integer_parameter(parameter)
                && auth.authenticated_roots.contains(&parameter.name)
                && writes.iter().any(|write| {
                    write.slot.same_storage_family(
                        guards
                            .iter()
                            .find(|guard| guard.candidate.contains(&parameter.name))
                            .map(|guard| &guard.slot)
                            .unwrap_or(&write.slot),
                    ) && matches!(write.kind, WriteKind::Increment | WriteKind::AddAssign | WriteKind::Assign)
                })
        });

    NonceAssessment {
        nonce_activity: candidate_activity || effective > 0,
        suspicious: multi_signature_gap
            || has_ineffective_nonce_guard
            || has_apparent_guard_without_effective_consumption
            || suspicious_unguarded_nonce_write
            || unchecked_narrow_wrap,
        rollback_sensitive,
        guarded_slots,
        consumed_slots,
        cleared_slots,
    }
}


/// `require(recipient == msg.sender)` with a signed `recipient`: the caller is the signed account, so
/// state keyed by `msg.sender` is keyed by a signed value.
/// A `view` or `pure` function cannot consume a nonce, so its use of one is checked at the caller.
fn can_change_state(model: &FunctionModel) -> bool {
    let header = model.source.split('{').next().unwrap_or("");
    !contains_word(header, "view") && !contains_word(header, "pure") && !contains_word(header, "constant")
}

/// A function that reverts unless the contract calls itself (`msg.sender == address(this)`), directly or
/// through a helper, is a step of another signed action and is not reachable with a signature of its own.
fn self_call_only(model: &FunctionModel, models: &BTreeMap<NodeID, FunctionModel>) -> bool {
    let requires_self = |source: &str| {
        let c = compact(source);
        c.contains("require(msg.sender==address(this)")
            || c.contains("require(address(this)==msg.sender")
            || c.contains("if(msg.sender!=address(this)") && super::signature_utils::body_reverts(
                &c[c.find("if(msg.sender!=address(this)").unwrap_or(0) + "if(msg.sender!=address(this)".len()..],
            )
            || c.contains("if(msg.sender!=address(this)||")
    };
    requires_self(&model.source)
        || model
            .calls
            .iter()
            .filter_map(|call| models.get(&call.callee))
            .any(|callee| requires_self(&callee.source) && !callee.entry_point)
}

fn with_sender_binding(model: &FunctionModel, auth: &AuthSummary) -> AuthSummary {
    let c = compact(&model.source);
    let bound = identifiers_in_text(&model.source).into_iter().any(|id| {
        auth.authenticated_roots.contains(&id)
            && id != "sender"
            && (c.contains(&format!("require({id}==msg.sender"))
                || c.contains(&format!("require(msg.sender=={id}"))
                || c.contains(&format!("if({id}!=msg.sender)revert"))
                || c.contains(&format!("if(msg.sender!={id})revert")))
    });
    let mut out = auth.clone();
    if bound {
        out.authenticated_roots.insert("msg".to_string());
        out.authenticated_roots.insert("sender".to_string());
    }
    out
}

/// Adds the state returned by helpers that are called inside the signed digest (e.g. `_useNonce(owner)`
/// in `abi.encode`) to the authenticated roots.
fn with_digest_helper_returns(
    model: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> AuthSummary {
    let mut out = auth.clone();
    for call in &model.calls {
        if auth.authenticated_roots.contains(&call.name) {
            out.authenticated_roots.extend(helper_return_identifiers(call, models, 3));
        }
    }
    out
}

/// The identifiers that `call` returns, in the caller's terms, following the helpers that the returned
/// expression calls in turn (`_messageToRecover(..)` -> `generateMessageToSign(..)` -> `spendNonce`).
fn helper_return_identifiers(
    call: &CallSite,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(callee) = models.get(&call.callee) else {
        return out;
    };
    let substitutions = parameter_substitutions(callee, call);
    let mut returned = BTreeSet::new();
    for expression in returned_expressions(&callee.source) {
        let expanded = expand_expression(&expression, &callee.assignments, 4);
        returned.extend(identifiers_in_text(&expanded));
        out.extend(identifiers_in_text(&substitute_identifiers(&expanded, &substitutions)));
    }
    if depth > 1 {
        for inner in callee.calls.iter().filter(|inner| returned.contains(&inner.name)) {
            for id in helper_return_identifiers(inner, models, depth - 1) {
                match substitutions.get(&id) {
                    Some(argument) => out.extend(identifiers_in_text(argument)),
                    None => {
                        out.insert(id);
                    }
                }
            }
        }
    }
    out
}

/// `require(hashTransaction(sender, nonce) == hash)` with a signed `hash`: the values hashed on the other
/// side are signed as well.
fn with_equality_binding(model: &FunctionModel, auth: &AuthSummary) -> AuthSummary {
    let mut out = auth.clone();
    for (condition, _) in extract_conditions(&model.source) {
        let mut atoms = Vec::new();
        split_condition_atoms(&condition, false, &mut atoms);
        for (atom, bypassable) in atoms {
            let atom = trim_outer_parens(atom.trim());
            let Some(index) = find_top_level_operator(atom, "==").filter(|_| !bypassable) else {
                continue;
            };
            let (left, right) = (atom[..index].trim(), atom[index + 2..].trim());
            for (signed, other) in [(left, right), (right, left)] {
                let signed_local = identifier_sequence(signed).len() == 1
                    && auth.authenticated_roots.contains(signed)
                    && !auth.principal_roots.contains(signed);
                if signed_local && other.contains('(') {
                    let expanded = expand_expression(other, &model.assignments, 4);
                    out.authenticated_roots.extend(identifiers_in_text(&expanded));
                }
            }
        }
    }
    out
}

/// The call at `pos` is one side of `==`/`!=` in its statement, and the other side is signed.
fn compared_with_signed_value(
    source: &str,
    pos: usize,
    auth: &AuthSummary,
    assignments: &HashMap<String, String>,
) -> bool {
    let pos = pos.min(source.len());
    let start = source[..pos].rfind([';', '{', '}']).map_or(0, |i| i + 1);
    let end = source[pos..].find(';').map_or(source.len(), |i| pos + i);
    let Some(open) = source[pos..end].find('(').map(|i| pos + i) else {
        return false;
    };
    let Some(close) = matching_delimiter(source, open, '(', ')') else {
        return false;
    };
    let before = &source[start..pos];
    let after = source.get(close + 1..end).unwrap_or("");
    let side = if let Some(i) = before.rfind("==").or_else(|| before.rfind("!=")) {
        before[..i].rsplit(['(', ',']).next().unwrap_or("")
    } else if let Some(i) = after.find("==").or_else(|| after.find("!=")) {
        after[i + 2..].split([')', ',']).next().unwrap_or("")
    } else {
        return false;
    };
    expression_is_authenticated(side, auth, assignments)
}

fn write_is_digest_bound_counter(
    source: &str,
    write: &WriteFact,
    writes: &[WriteFact],
    auth: &AuthSummary,
    assignments: &HashMap<String, String>,
) -> bool {
    // `keccak256(abi.encode(.., nonces[user]++, ..))` advances the counter whenever the digest that is
    // verified is computed, even inside the branch that verifies it.
    let in_digest = write.kind == WriteKind::Increment && inside_expression(source, write.pos);
    if write.conditional && !in_digest || !counter_write_advances(write, assignments) {
        return false;
    }
    let base_signed = auth.authenticated_roots.contains(&write.slot.base)
        || write
            .slot
            .field
            .as_ref()
            .is_some_and(|field| auth.authenticated_roots.contains(field));
    base_signed
        && slot_keys_authenticated(&write.slot, auth, assignments)
        && writes
            .iter()
            .rev()
            .find(|other| other.slot.same_storage_location(&write.slot))
            .is_some_and(|last| counter_write_advances(last, assignments))
}

/// The position is inside the arguments of a call rather than a statement of its own.
fn inside_expression(source: &str, pos: usize) -> bool {
    let Some(before) = source.get(..pos) else {
        return false;
    };
    let start = before.rfind(|c| matches!(c, ';' | '{' | '}')).map_or(0, |i| i + 1);
    let segment = &before[start..];
    segment.matches('(').count() > segment.matches(')').count()
}

fn counter_write_advances(write: &WriteFact, assignments: &HashMap<String, String>) -> bool {
    match write.kind {
        WriteKind::Increment => true,
        WriteKind::AddAssign => !expression_is_zero(&write.rhs),
        WriteKind::Assign => {
            let rhs = compact(&expand_expression(&write.rhs, assignments, 4));
            rhs.contains(&write.slot.base) && rhs.contains('+') && !rhs.contains('-')
        }
        _ => false,
    }
}

fn is_narrow_integer_parameter(parameter: &Parameter) -> bool {
    let raw = compact(&parameter.raw);
    [
        "uint8", "uint16", "uint24", "uint32", "uint40", "uint48", "uint56", "uint64",
        "int8", "int16", "int24", "int32", "int40", "int48", "int56", "int64",
    ]
    .iter()
    .any(|kind| raw.starts_with(kind))
}

fn collect_guards(
    model: &FunctionModel,
    auth: &AuthSummary,
    locals: &BTreeSet<String>,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
) -> Vec<GuardFact> {
    let mut out = Vec::new();
    for (condition, pos) in extract_conditions(&model.source) {
        let mut atoms = Vec::new();
        split_condition_atoms(&condition, false, &mut atoms);
        for (atom, bypassable) in atoms {
            if let Some(mut guard) = parse_guard_atom(
                &atom,
                pos,
                bypassable,
                model,
                auth,
                locals,
                models,
                helpers,
            ) {
                guard.slot = guard.slot.normalized(&model.assignments);
                if !out.iter().any(|existing: &GuardFact| {
                    existing.pos == guard.pos
                        && existing.kind == guard.kind
                        && existing.slot == guard.slot
                }) {
                    out.push(guard);
                }
            }
        }
    }
    out
}

fn parse_guard_atom(
    atom: &str,
    pos: usize,
    bypassable: bool,
    model: &FunctionModel,
    auth: &AuthSummary,
    locals: &BTreeSet<String>,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
) -> Option<GuardFact> {
    let trimmed = trim_outer_parens(atom.trim());

    if let Some(rest) = trimmed.strip_prefix('!') {
        let slot = resolve_slot_expression(rest, model, locals, models, helpers)?;
        let authenticated = slot_keys_authenticated(&slot, auth, &model.assignments);
        return Some(GuardFact {
            slot,
            kind: GuardKind::BoolClear,
            candidate: String::new(),
            mask: None,
            pos,
            bypassable,
            lossy: false,
            ahead: false,
            authenticated,
        });
    }

    for operator in ["==", "!=", ">=", "<=", ">", "<"] {
        let Some(index) = find_top_level_operator(trimmed, operator) else {
            continue;
        };
        let left = trimmed[..index].trim();
        let right = trimmed[index + operator.len()..].trim();

        if let Some((slot, mask)) = bitmap_side(left, model, locals, models, helpers) {
            if expression_is_zero(right) {
                let authenticated = slot_keys_authenticated(&slot, auth, &model.assignments)
                    && expression_is_authenticated(&mask, auth, &model.assignments);
                let clear = matches!(operator, "==" | "<=");
                return Some(GuardFact {
                    slot,
                    kind: if clear { GuardKind::BitmapClear } else { GuardKind::PresenceOnly },
                    candidate: String::new(),
                    mask: Some(mask),
                    pos,
                    bypassable,
                    lossy: false,
                    ahead: false,
                    authenticated,
                });
            }
        }
        if let Some((slot, mask)) = bitmap_side(right, model, locals, models, helpers) {
            if expression_is_zero(left) {
                let authenticated = slot_keys_authenticated(&slot, auth, &model.assignments)
                    && expression_is_authenticated(&mask, auth, &model.assignments);
                return Some(GuardFact {
                    slot,
                    kind: if operator == "==" { GuardKind::BitmapClear } else { GuardKind::PresenceOnly },
                    candidate: String::new(),
                    mask: Some(mask),
                    pos,
                    bypassable,
                    lossy: false,
                    ahead: false,
                    authenticated,
                });
            }
        }

        let left_slot = resolve_slot_expression(left, model, locals, models, helpers);
        let right_slot = resolve_slot_expression(right, model, locals, models, helpers);
        let mut ahead = false;
        let (slot, candidate, state_on_left) = match (left_slot, right_slot) {
            (Some(slot), None) => (slot, right.to_string(), true),
            (None, Some(slot)) => (slot, left.to_string(), false),
            (None, None) if operator == "==" => {
                let resolve = |side: &str| {
                    strip_increment(side).and_then(|base| resolve_slot_expression(base, model, locals, models, helpers))
                };
                ahead = true;
                match (resolve(left), resolve(right)) {
                    (Some(slot), None) => (slot, right.to_string(), true),
                    (None, Some(slot)) => (slot, left.to_string(), false),
                    _ => continue,
                }
            }
            _ => continue,
        };

        if operator == "==" && strip_increment(if state_on_left { left } else { right }).is_some() {
            ahead = true;
        }
        let lossy = comparison_is_lossy(left, right);
        let keys_authenticated = slot_keys_authenticated(&slot, auth, &model.assignments);
        let candidate_authenticated = expression_is_authenticated(&candidate, auth, &model.assignments);

        if matches!(operator, "==" | "!=") && expression_is_bool_or_zero(&candidate) {
            return Some(GuardFact {
                slot,
                kind: if operator == "==" && expression_is_false_or_zero(&candidate)
                    || operator == "!=" && expression_is_true_or_nonzero(&candidate)
                {
                    GuardKind::BoolClear
                } else {
                    GuardKind::PresenceOnly
                },
                candidate,
                mask: None,
                pos,
                bypassable,
                lossy,
                ahead: false,
                authenticated: keys_authenticated,
            });
        }

        let kind = if operator == "==" {
            GuardKind::Equality
        } else if (!state_on_left && operator == ">") || (state_on_left && operator == "<") {
            // candidate > state
            GuardKind::MonotonicGreater
        } else {
            GuardKind::PresenceOnly
        };

        return Some(GuardFact {
            slot,
            kind,
            candidate: candidate.clone(),
            mask: None,
            pos,
            bypassable,
            lossy,
            ahead,
            authenticated: keys_authenticated && candidate_authenticated,
        });
    }

    None
}

fn bitmap_side(
    expression: &str,
    model: &FunctionModel,
    locals: &BTreeSet<String>,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
) -> Option<(StateSlot, String)> {
    let index = find_top_level_operator(trim_outer_parens(expression), "&")?;
    let text = trim_outer_parens(expression);
    let left = text[..index].trim();
    let right = text[index + 1..].trim();
    if let Some(slot) = resolve_slot_expression(left, model, locals, models, helpers) {
        return Some((slot, right.to_string()));
    }
    resolve_slot_expression(right, model, locals, models, helpers)
        .map(|slot| (slot, left.to_string()))
}

fn resolve_slot_expression(
    expression: &str,
    model: &FunctionModel,
    locals: &BTreeSet<String>,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
) -> Option<StateSlot> {
    if let Some(slot) = extract_first_state_slot(
        expression,
        &model.assignments,
        &model.parameters,
        locals,
    ) {
        return Some(slot);
    }

    // Resolve simple internal state-reader helpers such as `_expected(signer)` by substituting the
    // callee parameters with the caller arguments.
    for call in &model.calls {
        if !contains_call(expression, &call.name) {
            continue;
        }
        let Some(helper) = helpers.get(&call.callee) else {
            continue;
        };
        let Some(slot) = &helper.returned_slot else {
            continue;
        };
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        return Some(instantiate_slot(slot, callee, call, &model.assignments));
    }
    None
}

fn collect_writes(
    source: &str,
    assignments: &HashMap<String, String>,
    parameters: &[Parameter],
    locals: &BTreeSet<String>,
) -> Vec<WriteFact> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    for statement in split_statements(source) {
        let pos = source[search_from..]
            .find(&statement)
            .map(|x| search_from + x)
            .unwrap_or(search_from);
        search_from = pos.saturating_add(statement.len());
        collect_writes_from_statement(
            &statement,
            pos,
            source,
            assignments,
            parameters,
            locals,
            &mut out,
        );
    }
    out
}

fn collect_writes_from_statement(
    statement: &str,
    pos: usize,
    whole_source: &str,
    assignments: &HashMap<String, String>,
    parameters: &[Parameter],
    locals: &BTreeSet<String>,
    out: &mut Vec<WriteFact>,
) {
    // A statement split at `;` can start with the `}` that closes the previous block; the write itself
    // starts after it.
    let mut rest = statement;
    loop {
        let trimmed = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '{' || c == '}');
        match ["else", "unchecked"].iter().find_map(|kw| {
            trimmed.strip_prefix(kw).filter(|r| !r.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
        }) {
            Some(after) => rest = after,
            None => {
                rest = trimmed;
                break;
            }
        }
    }
    // Offsets found in `statement` are added to `pos`; the write itself starts at `start`.
    let start = pos + (statement.len() - rest.len());
    // In `if (nonce != nonces[a]++) revert ..;` the only write is in the condition, which always runs.
    let mut head = statement.trim_start();
    while let Some(rest) = head
        .strip_prefix("unchecked")
        .or_else(|| head.strip_prefix('{'))
        .or_else(|| head.strip_prefix('}'))
    {
        head = rest.trim_start();
    }
    let revert_guard = head.strip_prefix("if").is_some_and(|rest| {
        let rest = rest.trim_start();
        rest.starts_with('(')
            && matching_delimiter(rest, 0, '(', ')')
                .is_some_and(|close| super::signature_utils::body_reverts(&rest[close + 1..]))
    });
    let conditional = is_inside_conditional_block(whole_source, start)
        || (contains_word(statement, "if") && !revert_guard);

    if let Some(delete_pos) = find_word_local(statement, "delete") {
        let tail = statement[delete_pos + "delete".len()..].trim_start();
        if let Some(slot) = extract_first_state_slot(tail, assignments, parameters, locals) {
            out.push(WriteFact {
                slot,
                kind: WriteKind::Delete,
                rhs: String::new(),
                pos: start,
                conditional,
            });
        }
    }

    for (needle, kind) in [
        ("|=", WriteKind::OrAssign),
        ("^=", WriteKind::XorAssign),
        ("&=", WriteKind::AndAssign),
        ("+=", WriteKind::AddAssign),
        ("-=", WriteKind::SubAssign),
    ] {
        let mut from = 0usize;
        while let Some(index) = statement[from..].find(needle).map(|x| from + x) {
            let lhs = lvalue_before(statement, index);
            if let Some(slot) = extract_first_state_slot(&lhs, assignments, parameters, locals) {
                let rhs = super::signature_utils::desugar_safemath(&expression_after_operator(statement, index + needle.len()));
                out.push(WriteFact {
                    slot,
                    kind,
                    rhs,
                    pos: pos + index,
                    conditional,
                });
            }
            from = index + needle.len();
        }
    }

    for (needle, kind) in [("++", WriteKind::Increment), ("--", WriteKind::Decrement)] {
        let mut from = 0usize;
        while let Some(index) = statement[from..].find(needle).map(|x| from + x) {
            let before = lvalue_before(statement, index);
            let after = statement[index + needle.len()..].trim_start();
            let slot = extract_first_state_slot(&before, assignments, parameters, locals)
                .or_else(|| extract_first_state_slot(after, assignments, parameters, locals));
            if let Some(slot) = slot {
                out.push(WriteFact {
                    slot,
                    kind,
                    rhs: String::new(),
                    pos: pos + index,
                    conditional,
                });
            }
            from = index + needle.len();
        }
    }

    // `counter.increment()` on an OpenZeppelin counter, possibly through a local storage pointer
    // (`Counters.Counter storage nonce = _nonces[owner]; nonce.increment();`).
    let mut from = 0usize;
    while let Some(index) = statement[from..].find(".increment()").map(|x| from + x) {
        let operand = operand_before(statement, index);
        let target = assignments.get(&operand).cloned().unwrap_or(operand);
        if let Some(slot) = extract_first_state_slot(&target, assignments, parameters, locals) {
            out.push(WriteFact {
                slot,
                kind: WriteKind::Increment,
                rhs: String::new(),
                pos: pos + index,
                conditional,
            });
        }
        from = index + ".increment()".len();
    }

    // Plain '=' is handled last. Skip comparisons and compound assignments.
    let bytes = statement.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'=' {
            continue;
        }
        let prev = index.checked_sub(1).and_then(|x| bytes.get(x)).copied();
        let next = bytes.get(index + 1).copied();
        if matches!(prev, Some(b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'|' | b'^' | b'&'))
            || next == Some(b'=')
        {
            continue;
        }
        let lhs = lvalue_before(statement, index);
        if let Some(slot) = extract_first_state_slot(&lhs, assignments, parameters, locals) {
            let rhs = super::signature_utils::desugar_safemath(&expression_after_operator(statement, index + 1));
            out.push(WriteFact {
                slot,
                kind: WriteKind::Assign,
                rhs,
                pos: pos + index,
                conditional,
            });
        }
    }

    dedup_writes(out);
}

fn append_instantiated_helper_guards(
    caller: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
    guards: &mut Vec<GuardFact>,
) {
    for call in &caller.calls {
        let Some(helper) = helpers.get(&call.callee) else {
            continue;
        };
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        // A pure helper (SafeMath.add's `require(c >= a)`) cannot read storage, so its checks never
        // guard authorization state.
        let header = callee.source.split('{').next().unwrap_or("");
        if contains_word(header, "pure") {
            continue;
        }
        for guard in &helper.guards {
            let mut instantiated = guard.clone();
            instantiated.slot = instantiate_slot(&guard.slot, callee, call, &caller.assignments);
            instantiated.candidate = instantiate_expression(
                &guard.candidate,
                callee,
                call,
                &caller.assignments,
            );
            instantiated.mask = guard.mask.as_ref().map(|mask| {
                instantiate_expression(mask, callee, call, &caller.assignments)
            });
            instantiated.pos = call.pos;
            instantiated.authenticated = match instantiated.kind {
                GuardKind::BoolClear =>
                    slot_keys_authenticated(&instantiated.slot, auth, &caller.assignments),
                GuardKind::BitmapClear =>
                    slot_keys_authenticated(&instantiated.slot, auth, &caller.assignments)
                        && instantiated
                            .mask
                            .as_ref()
                            .map(|mask| expression_is_authenticated(mask, auth, &caller.assignments))
                            .unwrap_or(false),
                GuardKind::Equality | GuardKind::MonotonicGreater =>
                    slot_keys_authenticated(&instantiated.slot, auth, &caller.assignments)
                        && expression_is_authenticated(
                            &instantiated.candidate,
                            auth,
                            &caller.assignments,
                        ),
                GuardKind::PresenceOnly => false,
            };
            if !guards.iter().any(|existing| {
                existing.pos == instantiated.pos
                    && existing.kind == instantiated.kind
                    && existing.slot == instantiated.slot
            }) {
                guards.push(instantiated);
            }
        }
    }
}

fn append_instantiated_helper_writes(
    caller: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
    writes: &mut Vec<WriteFact>,
) {
    for call in &caller.calls {
        let Some(helper) = helpers.get(&call.callee) else {
            continue;
        };
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        for write in &helper.writes {
            let mut instantiated = write.clone();
            instantiated.slot = instantiate_slot(&write.slot, callee, call, &caller.assignments);
            instantiated.rhs = instantiate_expression(&write.rhs, callee, call, &caller.assignments);
            instantiated.pos = call.pos;
            writes.push(instantiated);
        }
    }
    dedup_writes(writes);
}

fn instantiate_slot(
    slot: &StateSlot,
    callee: &FunctionModel,
    call: &CallSite,
    caller_assignments: &HashMap<String, String>,
) -> StateSlot {
    let substitutions = parameter_substitutions(callee, call);
    let keys = slot
        .keys
        .iter()
        .map(|key| {
            compact(&expand_expression(
                &substitute_identifiers(key, &substitutions),
                caller_assignments,
                4,
            ))
        })
        .collect();
    StateSlot {
        base: slot.base.clone(),
        keys,
        field: slot.field.clone(),
    }
}

fn instantiate_expression(
    expression: &str,
    callee: &FunctionModel,
    call: &CallSite,
    caller_assignments: &HashMap<String, String>,
) -> String {
    let substitutions = parameter_substitutions(callee, call);
    expand_expression(
        &substitute_identifiers(expression, &substitutions),
        caller_assignments,
        4,
    )
}

fn parameter_substitutions(callee: &FunctionModel, call: &CallSite) -> HashMap<String, String> {
    callee
        .parameters
        .iter()
        .enumerate()
        .filter_map(|(idx, param)| call.args.get(idx).map(|arg| (param.name.clone(), arg.clone())))
        .collect()
}

fn parse_returned_slot(
    source: &str,
    assignments: &HashMap<String, String>,
    parameters: &[Parameter],
    locals: &BTreeSet<String>,
) -> Option<StateSlot> {
    let mut from = 0usize;
    while let Some(pos) = find_word_from_local(source, "return", from) {
        let tail = &source[pos + "return".len()..];
        let end = tail.find(';').unwrap_or(tail.len());
        if let Some(slot) = extract_first_state_slot(&tail[..end], assignments, parameters, locals) {
            return Some(slot);
        }
        from = pos + "return".len();
    }
    None
}

fn write_is_effective_for_guard(
    guard: &GuardFact,
    write: &WriteFact,
    model: &FunctionModel,
    xor_postcondition: bool,
) -> bool {
    if write.conditional && !write_in_body_of_guard_if(&model.source, guard.pos, write.pos)
        || early_return_before_write(&model.source, guard.pos, write.pos)
    {
        return false;
    }
    let rhs = compact(&expand_expression(&write.rhs, &model.assignments, 4));
    let candidate = compact(&expand_expression(&guard.candidate, &model.assignments, 4));

    match guard.kind {
        GuardKind::Equality => match write.kind {
            WriteKind::Increment => true,
            WriteKind::AddAssign => !expression_is_zero(&rhs),
            WriteKind::Assign => {
                if rhs == candidate || rhs.is_empty() {
                    return guard.ahead && !rhs.is_empty();
                }
                expression_advances_value(&rhs, &candidate, &guard.slot)
            }
            _ => false,
        },
        GuardKind::MonotonicGreater => match write.kind {
            WriteKind::Assign => rhs == candidate || expression_contains_expr(&rhs, &candidate),
            WriteKind::Increment | WriteKind::AddAssign => true,
            _ => false,
        },
        GuardKind::BoolClear => match write.kind {
            WriteKind::Assign => expression_is_true_or_nonzero(&rhs),
            WriteKind::OrAssign => true,
            _ => false,
        },
        GuardKind::BitmapClear => match write.kind {
            WriteKind::OrAssign => guard
                .mask
                .as_ref()
                .map(|mask| expressions_equivalent(mask, &write.rhs, &model.assignments))
                .unwrap_or(true),
            WriteKind::XorAssign => {
                guard
                    .mask
                    .as_ref()
                    .map(|mask| expressions_equivalent(mask, &write.rhs, &model.assignments))
                    .unwrap_or(true)
                    || xor_postcondition
            }
            WriteKind::Assign => {
                let has_or = rhs.contains('|');
                has_or && guard.mask.as_ref().map(|m| compact(m)).map(|m| rhs.contains(&m)).unwrap_or(true)
            }
            _ => false,
        },
        GuardKind::PresenceOnly => false,
    }
}

/// `if (stored < nonce && ..) { stored = nonce; .. }`: the write runs exactly when the check that holds
/// the guard passes, so it consumes the authorization like a write after `require`.
fn write_in_body_of_guard_if(source: &str, guard_pos: usize, write_pos: usize) -> bool {
    let bytes = source.as_bytes();
    let mut from = 0;
    while let Some(rel) = source.get(from..).and_then(|tail| tail.find("if")) {
        let start = from + rel;
        from = start + 2;
        let word_start = start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let word_end = bytes.get(start + 2).is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        if !word_start || !word_end || start > guard_pos {
            continue;
        }
        let Some(open) = source[start + 2..].find('(').map(|i| start + 2 + i) else {
            continue;
        };
        if !source[start + 2..open].trim().is_empty() {
            continue;
        }
        let Some(close) = matching_delimiter(source, open, '(', ')') else {
            continue;
        };
        if !(start <= guard_pos && guard_pos < close) {
            continue;
        }
        let rest = &source[close + 1..];
        let lead = rest.len() - rest.trim_start().len();
        let body = close + 1 + lead;
        if !source[body..].starts_with('{') {
            return false;
        }
        return matching_delimiter(source, body, '{', '}').is_some_and(|end| body < write_pos && write_pos < end);
    }
    false
}

/// `nonces[a].add(1)` or `nonces[a] + 1` -> `nonces[a]`.
fn strip_increment(expression: &str) -> Option<&str> {
    let e = expression.trim();
    let positive = |text: &str| text.trim().parse::<u64>().is_ok_and(|n| n > 0);
    if let Some(open) = e.rfind(".add(") {
        let argument = e[open + ".add(".len()..].strip_suffix(')')?;
        return positive(argument).then(|| &e[..open]);
    }
    let plus = e.rfind('+')?;
    (positive(&e[plus + 1..]) && !e[..plus].trim_end().ends_with('+')).then(|| e[..plus].trim())
}

fn expression_advances_value(rhs: &str, candidate: &str, slot: &StateSlot) -> bool {
    if rhs.contains("+1") || rhs.contains("+2") || rhs.contains("+3") {
        return rhs.contains(candidate) || rhs.contains(&slot.base);
    }
    if rhs.contains("-0") || rhs.contains("+0") {
        return false;
    }
    false
}

/// Every recovery verifies the same digest (a multisig whose owners sign one transaction hash), so one
/// consumed nonce in that digest protects all the signatures.
fn signatures_share_one_digest(auth: &AuthSummary, assignments: &HashMap<String, String>) -> bool {
    let cores: BTreeSet<BTreeSet<String>> = auth
        .digests
        .iter()
        .map(|digest| {
            identifiers_in_text(&without_string_literals(&expand_expression(digest, assignments, 5)))
                .into_iter()
                .filter(|id| !is_hashing_builtin(id) && !matches!(id.as_str(), "toEthSignedMessageHash" | "ECDSA"))
                .collect()
        })
        .collect();
    cores.len() == 1
}

fn has_shared_digest_identity_guard(guards: &[GuardFact], writes: &[WriteFact]) -> bool {
    guards.iter().any(|guard| {
        guard.kind == GuardKind::BoolClear
            && guard.slot.keys.iter().any(|key| {
                let lower = key.to_ascii_lowercase();
                lower.contains("digest") || lower.contains("hash")
            })
            && writes
                .iter()
                .any(|write| write.slot.same_storage_location(&guard.slot))
    })
}

fn has_safe_xor_postcondition(
    source: &str,
    auth: &AuthSummary,
    assignments: &HashMap<String, String>,
) -> bool {
    if !source.contains("^=") {
        return false;
    }
    // Recognize the semantic shape `flipped = bitmap[...] ^= mask; require((flipped & mask) != 0)`.
    // Variable names are arbitrary: compare data dependencies rather than specific identifiers.
    for statement in split_statements(source) {
        let Some(xor) = statement.find("^=") else {
            continue;
        };
        let before = &statement[..xor];
        let assigned_local = before
            .rfind('=')
            .and_then(|eq| identifier_sequence(&before[..eq]).into_iter().last());
        let mask = expression_after_operator(&statement, xor + 2);
        let Some(local) = assigned_local else {
            continue;
        };
        if !expression_is_authenticated(&mask, auth, assignments) {
            continue;
        }
        let compact_source = compact(source);
        let pattern = format!("{}&{}", local, compact(&mask));
        if compact_source.contains(&pattern)
            && (compact_source.contains(&format!("{}!=0", pattern))
                || compact_source.contains(&format!("({})!=0", pattern)))
        {
            return true;
        }
    }
    false
}

fn guard_can_be_external_version_gate(
    guard: &GuardFact,
    entry: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
    auth: &AuthSummary,
) -> bool {
    if guard.kind != GuardKind::Equality || !guard.authenticated {
        return false;
    }
    for sibling in models.values() {
        if sibling.id == entry.id || sibling.scope != entry.scope || !sibling.entry_point {
            continue;
        }
        let locals = collect_local_names(&sibling.source, &sibling.parameters);
        let mut writes = collect_writes(
            &sibling.source,
            &sibling.assignments,
            &sibling.parameters,
            &locals,
        );
        append_instantiated_helper_writes(sibling, models, helpers, &mut writes);
        for write in writes {
            if !write.slot.same_storage_family(&guard.slot) {
                continue;
            }
            if matches!(write.kind, WriteKind::Increment | WriteKind::AddAssign)
                && principal_self_service_matches_guard(&guard.slot, &write.slot, auth)
            {
                return true;
            }
            if write.kind == WriteKind::Assign
                && sibling_has_monotonic_guard_for_write(sibling, &write)
                && principal_self_service_matches_guard(&guard.slot, &write.slot, auth)
            {
                return true;
            }
        }
    }
    false
}

fn principal_self_service_matches_guard(
    guarded: &StateSlot,
    mutated: &StateSlot,
    auth: &AuthSummary,
) -> bool {
    if guarded.base != mutated.base || guarded.field != mutated.field {
        return false;
    }
    if guarded.keys.is_empty() && mutated.keys.is_empty() {
        return true;
    }
    if guarded.keys.len() != mutated.keys.len() {
        return false;
    }
    guarded.keys.iter().zip(&mutated.keys).all(|(a, b)| {
        a == b
            || (b.contains("msg.sender")
                && expression_is_authenticated(a, auth, &HashMap::new()))
    })
}

fn has_dangerous_cross_function_mutation(
    entry: &FunctionModel,
    assessment: &NonceAssessment,
    models: &BTreeMap<NodeID, FunctionModel>,
    auth_summaries: &BTreeMap<NodeID, AuthSummary>,
    helpers: &BTreeMap<NodeID, StateHelperSummary>,
) -> bool {
    if assessment.guarded_slots.is_empty() {
        return false;
    }
    let entry_auth = auth_summaries.get(&entry.id).cloned().unwrap_or_default();
    // Slots the signed function itself decreases (a balance it spends) are amounts, not one-time state.
    let entry_locals = collect_local_names(&entry.source, &entry.parameters);
    let entry_decreases: Vec<StateSlot> =
        collect_writes(&entry.source, &entry.assignments, &entry.parameters, &entry_locals)
            .into_iter()
            .filter(|write| matches!(write.kind, WriteKind::SubAssign | WriteKind::Decrement))
            .map(|write| write.slot)
            .collect();
    // A replay needs every one-time check of the signature to pass again: reviving one used flag does
    // not help while a consumed nonce next to it stays consumed.
    let mut revived = vec![false; assessment.guarded_slots.len()];
    for sibling in models.values() {
        if sibling.id == entry.id || sibling.scope != entry.scope || !sibling.entry_point {
            continue;
        }
        let sibling_auth = auth_summaries.get(&sibling.id).cloned().unwrap_or_default();
        let locals = collect_local_names(&sibling.source, &sibling.parameters);
        let mut writes = collect_writes(
            &sibling.source,
            &sibling.assignments,
            &sibling.parameters,
            &locals,
        );
        append_instantiated_helper_writes(sibling, models, helpers, &mut writes);
        for write in writes {
            // A cancellation/invalidation API that mutates a separate state family is itself a
            // nonce-management bug when the signed execution path never consults that family.
            // This models disconnected cancellation state without depending on a benchmark name:
            // the generic cancellation semantic hint is only used to identify the mechanism; the
            // decisive condition is the missing state dependency in the authorization path.
            if slot_is_cancellation_family(&write.slot)
                && slot_keys_authenticated(&write.slot, &entry_auth, &sibling.assignments)
                && !reachable_reads_storage_family(entry, models, &write.slot)
            {
                return true;
            }

            let family: Vec<usize> = (0..assessment.guarded_slots.len())
                .filter(|&i| assessment.guarded_slots[i].same_storage_family(&write.slot))
                .collect();
            if family.is_empty() {
                continue;
            }
            if matches!(write.kind, WriteKind::SubAssign | WriteKind::Decrement)
                && entry_decreases.iter().any(|slot| slot.same_storage_family(&write.slot))
            {
                continue;
            }
            // A used-flag (checked zero/false) is revived only by clearing it; setting it to another
            // non-zero value marks it used as well.
            if write.kind == WriteKind::Assign
                && assessment.cleared_slots.iter().any(|slot| slot.same_storage_family(&write.slot))
                && !expression_is_false_or_zero(&compact(&expand_expression(&write.rhs, &sibling.assignments, 3)))
            {
                continue;
            }
            if mutation_is_reversible_or_decreasing(sibling, &write, &sibling_auth) {
                for i in family {
                    revived[i] = true;
                }
            }
        }
    }
    // The slots the function consumes are its replay protection; without any, every guarded slot counts.
    let required: Vec<usize> = (0..assessment.guarded_slots.len())
        .filter(|&i| {
            assessment
                .consumed_slots
                .iter()
                .any(|slot| slot.same_storage_location(&assessment.guarded_slots[i]))
        })
        .collect();
    if required.is_empty() {
        revived.iter().any(|&slot_revived| slot_revived)
    } else {
        required.iter().all(|&i| revived[i])
    }
}


fn slot_is_cancellation_family(slot: &StateSlot) -> bool {
    let lower = format!(
        "{}{}",
        slot.base.to_ascii_lowercase(),
        slot.field.as_deref().unwrap_or("").to_ascii_lowercase()
    );
    lower.contains("cancel") || lower.contains("invalidate") || lower.contains("revok")
}

/// The entry or a function it calls (up to four levels, e.g. `state(proposalId)`) reads the family.
fn reachable_reads_storage_family(
    entry: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    slot: &StateSlot,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut frontier = vec![entry];
    for _ in 0..5 {
        let mut next = Vec::new();
        for function in frontier {
            if !seen.insert(function.id) {
                continue;
            }
            if source_reads_storage_family(&function.source, slot) {
                return true;
            }
            next.extend(function.calls.iter().filter_map(|call| models.get(&call.callee)));
        }
        frontier = next;
    }
    false
}

fn source_reads_storage_family(source: &str, slot: &StateSlot) -> bool {
    let needle = match &slot.field {
        Some(field) => format!("{}", field),
        None => slot.base.clone(),
    };
    identifiers_in_text(source).contains(&needle)
}

fn mutation_is_reversible_or_decreasing(
    function: &FunctionModel,
    write: &WriteFact,
    auth: &AuthSummary,
) -> bool {
    match write.kind {
        WriteKind::Delete | WriteKind::SubAssign | WriteKind::Decrement | WriteKind::AndAssign => true,
        WriteKind::XorAssign => !has_safe_xor_postcondition(&function.source, auth, &function.assignments),
        WriteKind::Assign => {
            let rhs = compact(&expand_expression(&write.rhs, &function.assignments, 3));
            if expression_is_false_or_zero(&rhs) {
                return true;
            }
            // `nonces[a] = nonces[a] + 1` (possibly through a local copy) only moves the slot forward.
            let current = compact(&format!(
                "{}{}{}",
                write.slot.base,
                write.slot.keys.iter().map(|key| format!("[{key}]")).collect::<String>(),
                write.slot.field.as_deref().map(|field| format!(".{field}")).unwrap_or_default()
            ));
            if rhs.starts_with(&format!("{current}+")) || rhs.starts_with(&format!("({current})+")) {
                return false;
            }
            // Assigning an externally supplied value to an existing nonce slot is dangerous unless
            // the function proves the new value is strictly greater than current state.
            if expression_mentions_parameter(&rhs, &function.parameters)
                && !sibling_has_monotonic_guard_for_write(function, write)
            {
                return true;
            }
            // Restore/snapshot-style assignment from a different storage family can re-enable old
            // authorizations and is not a monotonic invalidation.
            if let Some(other_slot) = extract_first_state_slot(
                &write.rhs,
                &function.assignments,
                &function.parameters,
                &collect_local_names(&function.source, &function.parameters),
            ) {
                if !other_slot.same_storage_family(&write.slot) {
                    return true;
                }
            }
            false
        }
        WriteKind::AddAssign | WriteKind::Increment | WriteKind::OrAssign => false,
    }
}

fn sibling_has_monotonic_guard_for_write(function: &FunctionModel, write: &WriteFact) -> bool {
    let locals = collect_local_names(&function.source, &function.parameters);
    let dummy = AuthSummary {
        signature_verification: true,
        signature_count: 1,
        authenticated_roots: function.parameters.iter().map(|p| p.name.clone()).collect(),
        principal_roots: BTreeSet::new(),
        digests: BTreeSet::new(),
    };
    let guards = collect_guards(function, &dummy, &locals, &BTreeMap::new(), &BTreeMap::new());
    guards.iter().any(|guard| {
        guard.kind == GuardKind::MonotonicGreater
            && guard.slot.same_storage_location(&write.slot)
            && compact(&expand_expression(&write.rhs, &function.assignments, 3))
                == compact(&expand_expression(&guard.candidate, &function.assignments, 3))
    })
}

fn has_reverting_external_flow_after_consumption(
    source: &str,
    guards: &[GuardFact],
    writes: &[WriteFact],
) -> bool {
    let consume_pos = guards
        .iter()
        .filter_map(|guard| {
            writes
                .iter()
                .find(|write| write.pos >= guard.pos && write.slot.same_storage_location(&guard.slot))
                .map(|write| write.pos)
        })
        .min();
    let Some(consume_pos) = consume_pos else {
        return false;
    };
    let suffix = &source[consume_pos.min(source.len())..];
    let external_pos = [".call(", ".delegatecall(", "try "]
        .iter()
        .filter_map(|needle| suffix.find(needle))
        .min();
    let Some(external_pos) = external_pos else {
        return false;
    };
    let after = &suffix[external_pos..];
    let compact_after = compact(after);
    compact_after.contains("require(ok")
        || compact_after.contains("require(success")
        || compact_after.contains("assert(ok")
        || compact_after.contains("assert(success")
        || compact_after.contains("if(!ok){revert")
        || compact_after.contains("if(!success){revert")
        || (compact_after.contains("catch") && compact_after.contains("revert"))
}

fn write_looks_like_nonce_activity(
    write: &WriteFact,
    auth: &AuthSummary,
    assignments: &HashMap<String, String>,
) -> bool {
    if slot_has_nonce_semantic_hint(&write.slot) {
        return true;
    }
    match write.kind {
        // Unit counters and boolean flags are common business state. Without a nonce/authorization
        // semantic hint on the storage family, do not classify them as nonce state merely because
        // they increment or are set.
        WriteKind::Increment | WriteKind::Decrement | WriteKind::AddAssign | WriteKind::SubAssign => false,
        // Bitwise storage mutation is more characteristic of unordered nonce/invalidation state,
        // but still require authenticated storage keys to avoid flagging unrelated packed flags.
        WriteKind::OrAssign | WriteKind::XorAssign | WriteKind::AndAssign =>
            slot_keys_authenticated(&write.slot, auth, assignments),
        WriteKind::Assign => {
            let rhs = compact(&expand_expression(&write.rhs, assignments, 3));
            (expression_has_nonce_semantic_hint(&rhs)
                && expression_is_authenticated(&rhs, auth, assignments))
                || (rhs.contains("+1")
                    && expression_is_authenticated(&rhs, auth, assignments)
                    && slot_keys_authenticated(&write.slot, auth, assignments))
        }
        WriteKind::Delete => slot_keys_authenticated(&write.slot, auth, assignments),
    }
}

fn slot_has_nonce_semantic_hint(slot: &StateSlot) -> bool {
    semantic_hint(&slot.base)
        || slot.field.as_ref().map(|f| semantic_hint(f)).unwrap_or(false)
}

fn expression_has_nonce_semantic_hint(expression: &str) -> bool {
    identifiers_in_text(expression).iter().any(|id| semantic_hint(id))
}

fn semantic_hint(identifier: &str) -> bool {
    let lower = identifier.to_ascii_lowercase();
    [
        "nonce",
        "sequence",
        "seq",
        "authorization",
        "authorisation",
        "salt",
        "epoch",
        "session",
        "bitmap",
        "cancel",
        "invalidate",
        "invalidation",
        "used",
        "version",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn slot_keys_authenticated(
    slot: &StateSlot,
    auth: &AuthSummary,
    assignments: &HashMap<String, String>,
) -> bool {
    if slot.keys.is_empty() {
        return true;
    }
    slot.keys.iter().all(|key| {
        // `used[digest]` where `digest` is itself the signed value.
        let own = identifiers_in_text(key);
        if !own.is_empty()
            && own.iter().all(|id| auth.authenticated_roots.contains(id) || auth.principal_roots.contains(id))
        {
            return true;
        }
        let expanded = expand_expression(key, assignments, 4);
        let ids = identifiers_in_text(&without_string_literals(&expanded));
        ids.is_empty()
            || is_signature_recovery(&expanded)
            || ids.iter().all(|id| {
                is_nonsemantic_member_identifier(id)
                    || is_hashing_builtin(id)
                    || auth.authenticated_roots.contains(id)
                    || auth.principal_roots.contains(id)
                    // `msg.sender` inside a signed digest: the roots keep `sender`.
                    || id == "msg" && auth.authenticated_roots.contains("sender")
            })
            || (expanded.contains("msg.sender")
                && auth.principal_roots.iter().any(|p| p == "msg" || p == "sender"))
    })
}

/// `ecrecover(..)`, `ECDSA.recover(..)` or `hash.recover(..)` as a whole expression: the recovered
/// address is the signer, so a slot keyed by it is the signer's own namespace.
fn is_signature_recovery(expression: &str) -> bool {
    let mut text = compact(expression);
    while text.starts_with('(') && text.ends_with(')') {
        text = text[1..text.len() - 1].to_string();
    }
    let Some(open) = text.find('(') else {
        return false;
    };
    let callee = &text[..open];
    let is_recovery = callee == "ecrecover"
        || callee.ends_with(".recover")
        || callee.ends_with(".recoverSigner")
        || callee == "recoverSigner";
    is_recovery && matching_delimiter(&text, open, '(', ')') == Some(text.len() - 1)
}

fn expression_is_authenticated(
    expression: &str,
    auth: &AuthSummary,
    assignments: &HashMap<String, String>,
) -> bool {
    let expanded = expand_expression(expression, assignments, 5);
    let ids = identifiers_in_text(&expanded);
    ids.iter().any(|id| {
        auth.authenticated_roots.contains(id) || auth.principal_roots.contains(id)
    })
}

/// Removes the contents of string literals, whose words are not identifiers.
fn without_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    quote = None;
                    out.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                }
                out.push(ch);
            }
        }
    }
    out
}

/// Hashing and encoding built-ins carry no value of their own: `keccak256(abi.encode(a, b))` is as
/// signed as `a` and `b`.
fn is_hashing_builtin(id: &str) -> bool {
    matches!(
        id,
        "keccak256" | "sha256" | "abi" | "encode" | "encodePacked" | "encodeWithSelector" | "encodeWithSignature"
    )
}

fn is_nonsemantic_member_identifier(id: &str) -> bool {
    // Do not ignore msg.sender / tx.origin here.  They can be nonce principals, and treating them
    // as syntactic noise would make a relayer-scoped nonce look equivalent to a signer-scoped
    // nonce.  If msg.sender is genuinely the authenticated signer, principal discovery adds
    // `msg`/`sender` to principal_roots and the normal authentication check succeeds.
    matches!(id, "block" | "chainid" | "number" | "timestamp" | "this")
}

fn comparison_is_lossy(left: &str, right: &str) -> bool {
    let joined = format!("{} {}", compact(left), compact(right));
    joined.contains('%')
        || ["uint8(", "uint16(", "uint24(", "uint32(", "uint40(", "uint48(", "uint56(", "uint64("]
            .iter()
            .any(|cast| joined.contains(cast))
        || joined.contains("&0xff")
        || joined.contains("&255")
}

fn expression_is_zero(expression: &str) -> bool {
    matches!(compact(expression).as_str(), "0" | "uint256(0)" | "bytes32(0)")
}

fn expression_is_false_or_zero(expression: &str) -> bool {
    matches!(
        compact(expression).as_str(),
        "0" | "false" | "uint256(0)" | "bytes32(0)"
    )
}

fn expression_is_true_or_nonzero(expression: &str) -> bool {
    let c = compact(expression);
    c == "true" || c == "1" || (!c.is_empty() && !expression_is_false_or_zero(&c))
}

fn expression_is_bool_or_zero(expression: &str) -> bool {
    let c = compact(expression);
    c == "true" || c == "false" || c == "0" || c == "1" || c.starts_with("bytes32(0")
}

fn expressions_equivalent(
    a: &str,
    b: &str,
    assignments: &HashMap<String, String>,
) -> bool {
    compact(&expand_expression(a, assignments, 4)) == compact(&expand_expression(b, assignments, 4))
}

fn expression_contains_expr(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && compact(haystack).contains(&compact(needle))
}

fn expression_mentions_parameter(expression: &str, parameters: &[Parameter]) -> bool {
    let ids = identifiers_in_text(expression);
    parameters.iter().any(|p| ids.contains(&p.name))
}

fn parse_parameters(source: &str) -> Vec<Parameter> {
    let Some(function_pos) = find_word_from_local(source, "function", 0) else {
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
        .filter_map(|raw| {
            let identifiers = identifier_sequence(&raw);
            let name = identifiers.into_iter().rev().find(|id| !is_type_keyword(id))?;
            Some(Parameter { raw, name })
        })
        .collect()
}

fn collect_local_names(source: &str, parameters: &[Parameter]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = parameters.iter().map(|p| p.name.clone()).collect();
    out.extend(super::signature_utils::named_return_variables(source));
    let pieces = split_statements(source)
        .into_iter()
        .flat_map(|statement| super::signature_utils::block_pieces(&statement));
    for piece in pieces {
        let mut trimmed = piece.trim();
        // `for (uint256 i = 0; ...` declares `i`.
        if let Some(rest) = trimmed.strip_prefix("for") {
            trimmed = rest.trim_start().trim_start_matches('(').trim_start();
        }
        // The declared part ends at the first assignment (`=` that is not `==`, `<=`, `>=`, `!=`).
        let bytes = trimmed.as_bytes();
        let eq = (0..bytes.len()).find(|&i| {
            bytes[i] == b'='
                && bytes.get(i + 1) != Some(&b'=')
                && !matches!(i.checked_sub(1).map(|j| bytes[j]), Some(b'=' | b'!' | b'<' | b'>' | b':'))
        });
        let lhs = trimmed[..eq.unwrap_or(trimmed.len())].trim();
        if lhs.starts_with('(') {
            // `(bool ok, bytes memory ret) = ..`
            for part in super::signature_utils::split_top_level(lhs.trim_start_matches('(').trim_end_matches(')'), ',') {
                let ids = identifier_sequence(&part);
                if ids.len() >= 2 && is_type_keyword(&ids[0]) {
                    out.extend(ids.last().cloned());
                }
            }
            continue;
        }
        if lhs.contains('[') && !lhs.contains("[]") || lhs.contains('.') {
            continue;
        }
        let ids = identifier_sequence(lhs);
        if ids.len() < 2 {
            continue;
        }
        // Value-type declarations. A storage pointer is not a local (writes through it change
        // contract state), and struct-typed memory values are left out: expanding them through their
        // member assignments can grow without bound.
        if is_type_keyword(&ids[0]) && !contains_word(lhs, "storage") {
            out.extend(ids.last().cloned());
        }
    }
    out
}

/// Locals of a struct type in memory or calldata (`Request memory req`): their fields are not contract
/// state, so a check such as `!_exists(req.tokenId)` is not a check of a state slot named `req`.
fn memory_struct_names(source: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for piece in split_statements(source).into_iter().flat_map(|statement| super::signature_utils::block_pieces(&statement)) {
        let declared = piece.split('=').next().unwrap_or_default();
        let ids = identifier_sequence(declared);
        if ids.len() == 3 && !is_type_keyword(&ids[0]) && matches!(ids[1].as_str(), "memory" | "calldata") {
            out.insert(ids[2].clone());
        }
    }
    out
}

fn is_type_keyword(id: &str) -> bool {
    matches!(
        id,
        "address" | "bool" | "string" | "bytes" | "memory" | "calldata" | "storage" | "payable"
    ) || id.starts_with("uint")
        || id.starts_with("int")
        || id.starts_with("bytes")
}

fn extract_first_state_slot(
    expression: &str,
    assignments: &HashMap<String, String>,
    parameters: &[Parameter],
    locals: &BTreeSet<String>,
) -> Option<StateSlot> {
    let bytes = expression.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !is_ident_start(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < bytes.len() && is_ident_continue(bytes[i]) {
            i += 1;
        }
        let base = &expression[start..i];
        // Skip the tail of a number literal (`x7fff…` in `0x7fff…`) and language identifiers.
        if is_language_identifier(base) || (start > 0 && bytes[start - 1].is_ascii_digit()) {
            continue;
        }
        let mut cursor = i;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let mut keys = Vec::new();
        while cursor < bytes.len() && bytes[cursor] == b'[' {
            let close = matching_delimiter(expression, cursor, '[', ']')?;
            keys.push(expression[cursor + 1..close].trim().to_string());
            cursor = close + 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
        }
        let mut field = None;
        if cursor < bytes.len() && bytes[cursor] == b'.' {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < bytes.len() && is_ident_start(bytes[cursor]) {
                let field_start = cursor;
                cursor += 1;
                while cursor < bytes.len() && is_ident_continue(bytes[cursor]) {
                    cursor += 1;
                }
                field = Some(expression[field_start..cursor].to_string());
            }
        }

        // `Lib.recoverChecked(...)` or `token.balanceOf(...)` is a call, not a storage slot.
        let mut after_field = cursor;
        while after_field < bytes.len() && bytes[after_field].is_ascii_whitespace() {
            after_field += 1;
        }
        if field.is_some() && after_field < bytes.len() && bytes[after_field] == b'(' {
            i = cursor;
            continue;
        }

        if !keys.is_empty() || field.is_some() {
            if locals.contains(base) || parameters.iter().any(|p| p.name == base) {
                continue;
            }
            return Some(
                StateSlot {
                    base: base.to_string(),
                    keys,
                    field,
                }
                .normalized(assignments),
            );
        }
    }

    // Scalar state variable: accept only when the whole expression reduces to one identifier that
    // is not a parameter/local. This is required for deliberately single-authority global nonce
    // designs without turning arbitrary arithmetic expressions into storage slots.
    let trimmed = trim_outer_parens(expression.trim());
    let ids = identifier_sequence(trimmed);
    if ids.len() == 1 {
        let base = ids[0].clone();
        if !locals.contains(&base)
            && !parameters.iter().any(|p| p.name == base)
            && !is_language_identifier(&base)
        {
            return Some(StateSlot {
                base,
                keys: Vec::new(),
                field: None,
            });
        }
    }
    None
}

fn is_language_identifier(id: &str) -> bool {
    matches!(
        id,
        "require"
            | "assert"
            | "revert"
            | "if"
            | "else"
            | "return"
            | "keccak256"
            | "abi"
            | "encode"
            | "encodePacked"
            | "ecrecover"
            | "type"
            | "address"
            | "uint256"
            | "uint8"
            | "true"
            | "false"
            | "msg"
            | "tx"
            | "block"
    )
}

fn extract_conditions(source: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for keyword in ["require", "assert", "if"] {
        let mut from = 0usize;
        while let Some(pos) = find_word_from_local(source, keyword, from) {
            let Some(open_rel) = source[pos + keyword.len()..].find('(') else {
                break;
            };
            let open = pos + keyword.len() + open_rel;
            let Some(close) = matching_delimiter(source, open, '(', ')') else {
                break;
            };
            let raw = &source[open + 1..close];
            let condition = if keyword == "require" || keyword == "assert" {
                split_top_level(raw, ',').into_iter().next().unwrap_or_default()
            } else if super::signature_utils::body_reverts(&source[close + 1..]) {
                // `if (cond) revert ..;` is `require(!cond)`.
                super::signature_utils::negate_condition(raw)
            } else {
                raw.to_string()
            };
            out.push((condition, pos));
            from = close + 1;
        }
    }
    out.sort_by_key(|(_, pos)| *pos);
    out
}

fn split_condition_atoms(condition: &str, inherited_bypass: bool, out: &mut Vec<(String, bool)>) {
    if let Some(parts) = split_top_level_operator(condition, "||") {
        for part in parts {
            split_condition_atoms(&part, true, out);
        }
        return;
    }
    if let Some(parts) = split_top_level_operator(condition, "&&") {
        for part in parts {
            split_condition_atoms(&part, inherited_bypass, out);
        }
        return;
    }
    out.push((condition.trim().to_string(), inherited_bypass));
}

fn split_top_level_operator(text: &str, operator: &str) -> Option<Vec<String>> {
    let bytes = text.as_bytes();
    let op = operator.as_bytes();
    let mut p = 0i32;
    let mut b = 0i32;
    let mut c = 0i32;
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + op.len() <= bytes.len() {
        match bytes[i] {
            b'(' => p += 1,
            b')' => p -= 1,
            b'[' => b += 1,
            b']' => b -= 1,
            b'{' => c += 1,
            b'}' => c -= 1,
            _ => {}
        }
        if p == 0 && b == 0 && c == 0 && &bytes[i..i + op.len()] == op {
            parts.push(text[start..i].to_string());
            start = i + op.len();
            i += op.len();
            continue;
        }
        i += 1;
    }
    if parts.is_empty() {
        None
    } else {
        parts.push(text[start..].to_string());
        Some(parts)
    }
}

fn trim_outer_parens(mut text: &str) -> &str {
    loop {
        let trimmed = text.trim();
        if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
            return trimmed;
        }
        let Some(close) = matching_delimiter(trimmed, 0, '(', ')') else {
            return trimmed;
        };
        if close != trimmed.len() - 1 {
            return trimmed;
        }
        text = &trimmed[1..trimmed.len() - 1];
    }
}

fn contains_call(expression: &str, name: &str) -> bool {
    let compact_expression = compact(expression);
    compact_expression.contains(&format!("{}(", name))
}

fn lvalue_before(statement: &str, operator_pos: usize) -> String {
    let prefix = &statement[..operator_pos];
    let mut start = 0usize;
    for (idx, ch) in prefix.char_indices() {
        if matches!(ch, ';' | '{' | '}' | ',') {
            start = idx + ch.len_utf8();
        }
    }
    let fragment = prefix[start..].trim();
    if let Some(eq) = fragment.rfind('=') {
        fragment[eq + 1..].trim().to_string()
    } else {
        fragment.to_string()
    }
}

fn expression_after_operator(statement: &str, start: usize) -> String {
    let tail = &statement[start..];
    let mut p = 0i32;
    let mut b = 0i32;
    for (idx, ch) in tail.char_indices() {
        match ch {
            '(' => p += 1,
            ')' => {
                if p == 0 && b == 0 {
                    return tail[..idx].trim().to_string();
                }
                p -= 1;
            }
            '[' => b += 1,
            ']' => b -= 1,
            ';' | ',' if p == 0 && b == 0 => return tail[..idx].trim().to_string(),
            '}' if p == 0 && b == 0 => return tail[..idx].trim().to_string(),
            _ => {}
        }
    }
    tail.trim().trim_end_matches(';').trim().to_string()
}

fn dedup_writes(writes: &mut Vec<WriteFact>) {
    let mut seen = BTreeSet::new();
    writes.retain(|write| {
        seen.insert((
            write.pos,
            write.slot.clone(),
            write.kind as u8,
            compact(&write.rhs),
        ))
    });
}

fn early_return_before_write(source: &str, guard_pos: usize, write_pos: usize) -> bool {
    if write_pos <= guard_pos || write_pos > source.len() {
        return false;
    }
    let between = &source[guard_pos..write_pos];
    between.contains("return;") && between.contains("if")
}

fn is_inside_conditional_block(source: &str, pos: usize) -> bool {
    super::signature_utils::inside_conditional_body(source, pos)
}

fn find_word_local(text: &str, word: &str) -> Option<usize> {
    find_word_from_local(text, word, 0)
}

fn find_word_from_local(text: &str, word: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let needle = word.as_bytes();
    if needle.is_empty() || from >= bytes.len() {
        return None;
    }
    let mut i = from;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let left_ok = i == 0 || !is_ident_continue(bytes[i - 1]);
            let right_ok = i + needle.len() == bytes.len()
                || !is_ident_continue(bytes[i + needle.len()]);
            if left_ok && right_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_ident_start(ch: u8) -> bool {
    ch == b'_' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: u8) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit()
}

#[cfg(test)]
mod nonce_management_tests {
    use crate::detect::detector::IssueDetector;

    use super::*;

    #[test]
    fn semantic_hint_is_not_name_only_classification() {
        assert!(semantic_hint("authorizationCounter"));
        assert!(!semantic_hint("balance"));
    }

    #[test]
    fn lossy_nonce_comparison_detects_cast_and_modulo() {
        assert!(comparison_is_lossy("uint8(value)", "uint8(state[user])"));
        assert!(comparison_is_lossy("value % 16", "state[user] % 16"));
        assert!(!comparison_is_lossy("value", "state[user]"));
    }

    #[test]
    fn condition_split_marks_or_guard_as_bypassable() {
        let mut atoms = Vec::new();
        split_condition_atoms("legacy || value == state[user]", false, &mut atoms);
        assert_eq!(atoms.len(), 2);
        assert!(atoms.iter().all(|(_, bypass)| *bypass));
    }

    #[test]
    fn parses_nested_storage_slot() {
        let params = parse_parameters(
            "function f(address signer, uint256 value) external { require(value == lane[signer][1]); }",
        );
        let locals: BTreeSet<String> = params.iter().map(|p| p.name.clone()).collect();
        let slot = extract_first_state_slot(
            "lane[signer][1]",
            &HashMap::new(),
            &params,
            &locals,
        )
        .unwrap();
        assert_eq!(slot.base, "lane");
        assert_eq!(slot.keys.len(), 2);
    }

    #[test]
    fn safe_monotonic_sequence_write_is_effective() {
        let guard = GuardFact {
            slot: StateSlot {
                base: "state".into(),
                keys: vec!["signer".into()],
                field: None,
            },
            kind: GuardKind::MonotonicGreater,
            candidate: "seq".into(),
            mask: None,
            pos: 1,
            bypassable: false,
            lossy: false,
            ahead: false,
            authenticated: true,
        };
        let model = FunctionModel {
            id: 1,
            scope: 1,
            source: "require(seq > state[signer]); state[signer] = seq;".into(),
            entry_point: true,
            parameters: vec![],
            assignments: HashMap::new(),
            calls: vec![],
            direct_auth: AuthSummary::default(),
        };
        let write = WriteFact {
            slot: guard.slot.clone(),
            kind: WriteKind::Assign,
            rhs: "seq".into(),
            pos: 30,
            conditional: false,
        };
        assert!(write_is_effective_for_guard(&guard, &write, &model, false));
    }

    #[test]
    fn same_value_write_does_not_consume_nonce() {
        let guard = GuardFact {
            slot: StateSlot {
                base: "state".into(),
                keys: vec!["signer".into()],
                field: None,
            },
            kind: GuardKind::Equality,
            candidate: "seq".into(),
            mask: None,
            pos: 1,
            bypassable: false,
            lossy: false,
            ahead: false,
            authenticated: true,
        };
        let model = FunctionModel {
            id: 1,
            scope: 1,
            source: "require(seq == state[signer]); state[signer] = seq;".into(),
            entry_point: true,
            parameters: vec![],
            assignments: HashMap::new(),
            calls: vec![],
            direct_auth: AuthSummary::default(),
        };
        let write = WriteFact {
            slot: guard.slot.clone(),
            kind: WriteKind::Assign,
            rhs: "seq".into(),
            pos: 30,
            conditional: false,
        };
        assert!(!write_is_effective_for_guard(&guard, &write, &model, false));
    }

    fn run(path: &str) -> usize {
        let context = crate::detect::test_utils::load_solidity_source_unit(path);
        let mut detector = NonceManagementDetector::default();
        detector.detect(&context).unwrap();
        detector.instances().len()
    }

    #[test]
    fn detects_nonce_omitted_from_digest() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceNotAuthenticated.sol"),
            1
        );
    }

    #[test]
    fn accepts_correct_sequential_nonce() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceSequentialSafe.sol"),
            0
        );
    }

    #[test]
    fn detects_checked_but_not_consumed() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceNotConsumed.sol"),
            1
        );
    }

    #[test]
    fn detects_wrong_principal_update() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceWrongPrincipal.sol"),
            1
        );
    }

    #[test]
    fn detects_revert_rollback() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceRollback.sol"),
            1
        );
    }

    #[test]
    fn accepts_non_reverting_failure_handling() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceFailureSafe.sol"),
            0
        );
    }

    #[test]
    fn accepts_random_authorization_id() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/AuthorizationIdSafe.sol"),
            0
        );
    }

    #[test]
    fn accepts_unordered_bitmap_nonce() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/BitmapNonceSafe.sol"),
            0
        );
    }

    #[test]
    fn accepts_implicit_nonce_consumption() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceImplicitConsumptionSafe.sol"),
            0
        );
    }

    #[test]
    fn accepts_library_recovery_with_literal_bound() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceLibraryRecoverSafe.sol"),
            0
        );
    }

    #[test]
    fn detects_reset_of_implicitly_consumed_nonce() {
        assert_eq!(
            run("../tests/contract-playground/src/nonce-management/NonceImplicitReset.sol"),
            1
        );
    }

    #[test]
    fn accepts_nonce_of_recovered_signer() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/CompoundDelegate.sol"), 0);
    }

    #[test]
    fn accepts_vote_once_through_storage_pointer() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/GovernorVote.sol"), 0);
    }

    #[test]
    fn accepts_safemath_nonce_after_comment() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/MetaTxSafeMathComment.sol"), 0);
    }

    #[test]
    fn accepts_signature_in_two_encodings() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/AnyswapPermit.sol"), 0);
    }

    #[test]
    fn accepts_solmate_permit_in_unchecked_block() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/SolmatePermit.sol"), 0);
    }

    #[test]
    fn accepts_nonce_advanced_in_revert_guard() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/RevertGuardDelegate.sol"), 0);
    }

    #[test]
    fn accepts_nonce_compared_with_use_nonce() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/VotesUseNonce.sol"), 0);
    }

    #[test]
    fn handles_multibyte_characters() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/UnicodeStrings.sol"), 0);
    }

    #[test]
    fn accepts_common_safe_nonce_patterns() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/NonceSafePatterns.sol"), 0);
    }

    #[test]
    fn detects_used_flag_never_checked() {
        assert_eq!(run("../tests/contract-playground/src/signature-patterns/NonceUsedFlagNeverChecked.sol"), 1);
    }
}
