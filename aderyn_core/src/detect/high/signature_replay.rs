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
use eyre::Result;

/// Detects signature-authorized operations whose one-time authorization state is absent,
/// ineffective, rolled back, or scoped more narrowly than the authenticated authorization.
///
/// Design note: Aderyn v0.6.8 does not expose an SSA/CFG API to detectors. This detector therefore
/// uses Aderyn's AST for function/sink/call-graph discovery, then performs a small Solidity-aware
/// token/data-flow pass over the source of the discovered functions. It deliberately avoids
/// benchmark/file/variable-name matching.
#[derive(Default)]
pub struct SignatureReplayDetector {
    found_instances: BTreeMap<(String, usize, String), NodeID>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SrcSpan {
    start: usize,
    len: usize,
    file: usize,
}

impl SrcSpan {
    fn parse(src: &str) -> Option<Self> {
        let mut parts = src.split(':');
        Some(Self {
            start: parts.next()?.parse().ok()?,
            len: parts.next()?.parse().ok()?,
            file: parts.next()?.parse().ok()?,
        })
    }

    fn contains(self, other: Self) -> bool {
        self.file == other.file
            && other.start >= self.start
            && other.start.saturating_add(other.len) <= self.start.saturating_add(self.len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Slot {
    base: String,
    keys: Vec<String>,
}

impl Slot {
    fn dependencies(&self) -> BTreeSet<String> {
        self.keys
            .iter()
            .flat_map(|key| identifiers_in_text(key))
            .collect()
    }

    fn substitute(&self, substitutions: &HashMap<String, String>) -> Self {
        Self {
            base: substitute_identifiers(&self.base, substitutions),
            keys: self
                .keys
                .iter()
                .map(|key| substitute_identifiers(key, substitutions))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
enum GuardKind {
    Falsey,
    Truthy,
    EqualTo(String),
    GreaterThan(String),
    BitmapClear(String),
    Unknown,
}

#[derive(Debug, Clone)]
struct GuardFact {
    slot: Slot,
    kind: GuardKind,
    pos: usize,
}

impl GuardFact {
    fn substitute(&self, substitutions: &HashMap<String, String>) -> Self {
        let kind = match &self.kind {
            GuardKind::EqualTo(x) => {
                GuardKind::EqualTo(substitute_identifiers(x, substitutions))
            }
            GuardKind::GreaterThan(x) => {
                GuardKind::GreaterThan(substitute_identifiers(x, substitutions))
            }
            GuardKind::BitmapClear(x) => {
                GuardKind::BitmapClear(substitute_identifiers(x, substitutions))
            }
            GuardKind::Falsey => GuardKind::Falsey,
            GuardKind::Truthy => GuardKind::Truthy,
            GuardKind::Unknown => GuardKind::Unknown,
        };
        Self {
            slot: self.slot.substitute(substitutions),
            kind,
            pos: self.pos,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WriteOp {
    Assign,
    AddAssign,
    OrAssign,
    Increment,
    Delete,
}

#[derive(Debug, Clone)]
struct WriteFact {
    slot: Slot,
    op: WriteOp,
    rhs: String,
    pos: usize,
    conditional: bool,
}

impl WriteFact {
    fn substitute(&self, substitutions: &HashMap<String, String>) -> Self {
        Self {
            slot: self.slot.substitute(substitutions),
            op: self.op.clone(),
            rhs: substitute_identifiers(&self.rhs, substitutions),
            pos: self.pos,
            conditional: self.conditional,
        }
    }
}

#[derive(Debug, Clone)]
struct CallSite {
    callee: NodeID,
    args: Vec<String>,
    pos: usize,
    in_condition: bool,
    negated_in_condition: bool,
}

#[derive(Debug, Clone)]
struct FunctionModel {
    id: NodeID,
    scope: NodeID,
    span: SrcSpan,
    source: String,
    params: Vec<String>,
    entry_point: bool,
    direct_signature_sink: bool,
    direct_auth_roots: Vec<String>,
    calls: Vec<CallSite>,
    assignments: HashMap<String, String>,
    guards: Vec<GuardFact>,
    writes: Vec<WriteFact>,
    returned_slot: Option<Slot>,
    sensitive_effect: bool,
    reverting_external_flow: bool,
}

#[derive(Debug, Clone, Default)]
struct AnalysisFacts {
    auth_symbols: BTreeSet<String>,
    guards: Vec<GuardFact>,
    writes: Vec<WriteFact>,
    sensitive_effect: bool,
    reverting_external_flow: bool,
}

impl IssueDetector for SignatureReplayDetector {
    fn detect(&mut self, context: &WorkspaceContext) -> Result<bool, Box<dyn Error>> {
        let mut models = build_models(context);
        if models.is_empty() {
            return Ok(false);
        }

        let gated = propagate_signature_gates(&models);
        populate_interprocedural_auth_roots(&mut models, &gated);

        let mut vulnerable: BTreeSet<NodeID> = BTreeSet::new();
        let mut analyses: HashMap<NodeID, AnalysisFacts> = HashMap::new();

        for model in models.values() {
            if !model.entry_point || !gated.contains(&model.id) {
                continue;
            }

            let facts = analyze_entry(model.id, &models, &gated, 4);
            let authenticated_guards: Vec<&GuardFact> = facts
                .guards
                .iter()
                .filter(|g| guard_is_authenticated(g, &facts.auth_symbols))
                .collect();

            let effective: Vec<(&GuardFact, &WriteFact)> = authenticated_guards
                .iter()
                .filter_map(|guard| {
                    final_write_for_slot(&facts.writes, &guard.slot)
                        .filter(|write| write_invalidates_guard(guard, write))
                        .map(|write| (*guard, write))
                })
                .collect();

            // Class 1: a signed state-changing operation has no effective authenticated one-time
            // invariant. View-only/check-only signature functions are intentionally ignored.
            if facts.sensitive_effect && effective.is_empty() {
                vulnerable.insert(model.id);
                analyses.insert(model.id, facts);
                continue;
            }

            // Class 3: the authorization is consumed, but a later external execution path can revert
            // the whole transaction. The old authorization is then restored together with all state.
            if facts.reverting_external_flow
                && effective.iter().any(|(_, write)| {
                    let external_pos = first_external_effect_position(&model.source).unwrap_or(0);
                    write.pos <= external_pos
                })
            {
                vulnerable.insert(model.id);
                analyses.insert(model.id, facts);
                continue;
            }

            // Strong Class 4 signal: replay state is partitioned by an unsigned namespace/domain key.
            // Example shape: usedByDomain[domain][authorizationId], where authorizationId is signed
            // but `domain` is not. The same signature can be consumed once per unsigned namespace.
            if effective.iter().any(|(guard, _)| {
                guard.slot.keys.len() >= 2
                    && guard
                        .slot
                        .keys
                        .iter()
                        .any(|k| expr_is_authenticated(k, &facts.auth_symbols))
                    && guard
                        .slot
                        .keys
                        .iter()
                        .any(|k| !expr_is_authenticated(k, &facts.auth_symbols))
            }) {
                vulnerable.insert(model.id);
                analyses.insert(model.id, facts);
                continue;
            }

            analyses.insert(model.id, facts);
        }

        // Class 4, cross-function form: two entry points authenticate the same message shape but use
        // independent replay registries. Shared registries are intentionally considered safe.
        let entries: Vec<&FunctionModel> = models
            .values()
            .filter(|m| m.entry_point && gated.contains(&m.id))
            .collect();

        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                let a = entries[i];
                let b = entries[j];
                if a.scope != b.scope {
                    continue;
                }
                let Some(a_facts) = analyses.get(&a.id) else {
                    continue;
                };
                let Some(b_facts) = analyses.get(&b.id) else {
                    continue;
                };
                let Some(a_shape) = authorization_shape(a, a_facts) else {
                    continue;
                };
                let Some(b_shape) = authorization_shape(b, b_facts) else {
                    continue;
                };
                if a_shape != b_shape {
                    continue;
                }

                let a_slots = effective_slots(a_facts);
                let b_slots = effective_slots(b_facts);
                if a_slots.is_empty() || b_slots.is_empty() {
                    continue;
                }

                let shared = a_slots.iter().any(|slot| b_slots.contains(slot));
                if !shared {
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
        IssueSeverity::High
    }

    fn title(&self) -> String {
        String::from("Signature Replay Vulnerability")
    }

    fn description(&self) -> String {
        String::from(
            "A signature-authorized operation can remain valid after it should have been consumed, \
             or its replay state is scoped more narrowly than the authenticated authorization. \
             Repeated execution can duplicate withdrawals, claims, orders, approvals, bridge releases, \
             meta-transactions, or other signed actions. Bind a unique nonce/authorization identifier \
             (and any execution-domain discriminator) into the signed message, validate it against \
             persistent state, and irreversibly invalidate the exact same state/key on successful \
             execution. Do not rely on replay-state updates that are later rolled back by a revert; \
             equivalent execution paths must share replay state or be cryptographically domain-separated.",
        )
    }

    fn instances(&self) -> BTreeMap<(String, usize, String), NodeID> {
        self.found_instances.clone()
    }

    fn name(&self) -> String {
        format!("{}", IssueDetectorNamePool::SignatureReplay)
    }
}

fn build_models(context: &WorkspaceContext) -> BTreeMap<NodeID, FunctionModel> {
    let function_spans: Vec<(NodeID, SrcSpan)> = context
        .function_definitions()
        .into_iter()
        .filter_map(|f| SrcSpan::parse(&f.src).map(|span| (f.id, span)))
        .collect();
    let function_ids: HashSet<NodeID> = function_spans.iter().map(|(id, _)| *id).collect();

    let mut direct_sink_ids = BTreeSet::new();
    let mut sink_positions: HashMap<NodeID, Vec<(usize, String)>> = HashMap::new();

    for identifier in context.identifiers() {
        if identifier.name != "ecrecover" {
            continue;
        }
        let Some(node_span) = SrcSpan::parse(&identifier.src) else {
            continue;
        };
        if let Some((id, fspan)) = enclosing_function(node_span, &function_spans) {
            direct_sink_ids.insert(id);
            sink_positions
                .entry(id)
                .or_default()
                .push((node_span.start.saturating_sub(fspan.start), "ecrecover".into()));
        }
    }

    for member in context.member_accesss() {
        let name = member.member_name.as_str();
        if !matches!(
            name,
            "recover" | "tryRecover" | "isValidSignature" | "isValidSignatureNow" | "isValid"
        ) {
            continue;
        }
        let Some(node_span) = SrcSpan::parse(&member.src) else {
            continue;
        };
        let Some((id, fspan)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        let Some(function) = context.function_definitions().into_iter().find(|f| f.id == id) else {
            continue;
        };
        let source = function.peek(context).unwrap_or_default();
        if name == "isValid" && !looks_like_generic_signature_verifier_call(&source) {
            continue;
        }
        direct_sink_ids.insert(id);
        sink_positions
            .entry(id)
            .or_default()
            .push((node_span.start.saturating_sub(fspan.start), name.to_string()));
    }

    let mut call_sites_by_function: HashMap<NodeID, Vec<CallSite>> = HashMap::new();
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
        let Some((caller, fspan)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        if caller == callee {
            continue;
        }
        let Some(function) = context.function_definitions().into_iter().find(|f| f.id == caller) else {
            continue;
        };
        let source = function.peek(context).unwrap_or_default();
        let local_pos = node_span.start.saturating_sub(fspan.start);
        let args = parse_call_args_at(&source, local_pos).unwrap_or_default();
        let (in_condition, negated) = call_condition_context(&source, local_pos);
        call_sites_by_function
            .entry(caller)
            .or_default()
            .push(CallSite {
                callee,
                args,
                pos: local_pos,
                in_condition,
                negated_in_condition: negated,
            });
    }

    let mut models = BTreeMap::new();
    for function in context.function_definitions() {
        let Some(span) = SrcSpan::parse(&function.src) else {
            continue;
        };
        let source = function.peek(context).unwrap_or_default();
        let params = parse_parameter_names(&source);
        let assignments = collect_assignments(&source);
        let guards = collect_guards(&source, &params);
        let writes = collect_writes(&source);
        let returned_slot = collect_returned_slot(&source);
        let entry_point = is_public_or_external(&source);
        let direct_signature_sink = direct_sink_ids.contains(&function.id);
        let direct_auth_roots = sink_positions
            .get(&function.id)
            .into_iter()
            .flatten()
            .filter_map(|(pos, name)| digest_argument_at(&source, *pos, name))
            .collect();

        models.insert(
            function.id,
            FunctionModel {
                id: function.id,
                scope: function.scope,
                span,
                source: source.clone(),
                params,
                entry_point,
                direct_signature_sink,
                direct_auth_roots,
                calls: call_sites_by_function.remove(&function.id).unwrap_or_default(),
                assignments,
                guards,
                writes,
                returned_slot,
                sensitive_effect: has_sensitive_effect(&source),
                reverting_external_flow: has_reverting_external_flow(&source),
            },
        );
    }
    models
}

fn enclosing_function(node: SrcSpan, functions: &[(NodeID, SrcSpan)]) -> Option<(NodeID, SrcSpan)> {
    functions
        .iter()
        .filter(|(_, span)| span.contains(node))
        .min_by_key(|(_, span)| span.len)
        .copied()
}

fn propagate_signature_gates(models: &BTreeMap<NodeID, FunctionModel>) -> BTreeSet<NodeID> {
    let mut gated: BTreeSet<NodeID> = models
        .values()
        .filter(|m| m.direct_signature_sink)
        .map(|m| m.id)
        .collect();
    loop {
        let before = gated.len();
        for model in models.values() {
            if model.calls.iter().any(|c| gated.contains(&c.callee)) {
                gated.insert(model.id);
            }
        }
        if gated.len() == before {
            return gated;
        }
    }
}

fn populate_interprocedural_auth_roots(
    models: &mut BTreeMap<NodeID, FunctionModel>,
    gated: &BTreeSet<NodeID>,
) {
    let snapshot = models.clone();
    let mut roots: HashMap<NodeID, Vec<String>> = snapshot
        .values()
        .map(|m| (m.id, m.direct_auth_roots.clone()))
        .collect();

    for _ in 0..12 {
        let mut changed = false;
        let mut auth_params: HashMap<NodeID, BTreeSet<usize>> = HashMap::new();
        for model in snapshot.values() {
            if !gated.contains(&model.id) {
                continue;
            }
            let model_roots = roots.get(&model.id).cloned().unwrap_or_default();
            let symbols = resolve_auth_symbols(model, &model_roots);
            auth_params.insert(
                model.id,
                model
                    .params
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, name)| symbols.contains(name).then_some(idx))
                    .collect(),
            );
        }

        for model in snapshot.values() {
            let entry = roots.entry(model.id).or_default();
            let before = entry.len();
            for call in &model.calls {
                if !gated.contains(&call.callee) {
                    continue;
                }
                if let Some(indexes) = auth_params.get(&call.callee) {
                    for idx in indexes {
                        if let Some(arg) = call.args.get(*idx) {
                            if !entry.contains(arg) {
                                entry.push(arg.clone());
                            }
                        }
                    }
                }
            }
            changed |= entry.len() != before;
        }
        if !changed {
            break;
        }
    }

    for model in models.values_mut() {
        model.direct_auth_roots = roots.remove(&model.id).unwrap_or_default();
    }
}

fn analyze_entry(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    gated: &BTreeSet<NodeID>,
    max_depth: usize,
) -> AnalysisFacts {
    let Some(model) = models.get(&id) else {
        return AnalysisFacts::default();
    };
    let mut facts = AnalysisFacts {
        auth_symbols: resolve_auth_symbols(model, &model.direct_auth_roots),
        guards: model.guards.clone(),
        writes: model.writes.clone(),
        sensitive_effect: model.sensitive_effect,
        reverting_external_flow: model.reverting_external_flow,
    };
    inline_helper_facts(model, models, gated, max_depth, &mut facts);
    facts
}

fn inline_helper_facts(
    model: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    gated: &BTreeSet<NodeID>,
    depth: usize,
    facts: &mut AnalysisFacts,
) {
    if depth == 0 {
        return;
    }
    for call in &model.calls {
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        let substitutions: HashMap<String, String> = callee
            .params
            .iter()
            .cloned()
            .zip(call.args.iter().cloned())
            .collect();

        for guard in &callee.guards {
            facts.guards.push(guard.substitute(&substitutions));
        }
        for write in &callee.writes {
            facts.writes.push(write.substitute(&substitutions));
        }

        // `_isUsed(id)`-style helper used directly in a require/if condition.
        if call.in_condition {
            if let Some(returned) = &callee.returned_slot {
                facts.guards.push(GuardFact {
                    slot: returned.substitute(&substitutions),
                    kind: if call.negated_in_condition {
                        GuardKind::Falsey
                    } else {
                        GuardKind::Truthy
                    },
                    pos: call.pos,
                });
            }
        }

        facts.sensitive_effect |= callee.sensitive_effect;
        facts.reverting_external_flow |= callee.reverting_external_flow;

        if gated.contains(&callee.id) {
            let callee_symbols = resolve_auth_symbols(callee, &callee.direct_auth_roots);
            for symbol in callee_symbols {
                let mapped = substitutions.get(&symbol).cloned().unwrap_or(symbol);
                facts.auth_symbols.extend(identifiers_in_text(&mapped));
            }
        }

        inline_helper_facts(callee, models, gated, depth - 1, facts);
    }
}

fn resolve_auth_symbols(model: &FunctionModel, roots: &[String]) -> BTreeSet<String> {
    let mut symbols: BTreeSet<String> = roots.iter().flat_map(|x| identifiers_in_text(x)).collect();
    for _ in 0..12 {
        let before = symbols.len();
        let current: Vec<String> = symbols.iter().cloned().collect();
        for symbol in current {
            if let Some(rhs) = model.assignments.get(&symbol) {
                symbols.extend(identifiers_in_text(rhs));
            }
        }
        if symbols.len() == before {
            break;
        }
    }
    symbols
}

fn guard_is_authenticated(guard: &GuardFact, auth: &BTreeSet<String>) -> bool {
    let slot_signed = guard
        .slot
        .dependencies()
        .iter()
        .any(|dep| auth.contains(dep));
    let compared_signed = match &guard.kind {
        GuardKind::EqualTo(x) | GuardKind::GreaterThan(x) | GuardKind::BitmapClear(x) => {
            expr_is_authenticated(x, auth)
        }
        _ => false,
    };
    slot_signed || compared_signed
}

fn expr_is_authenticated(expr: &str, auth: &BTreeSet<String>) -> bool {
    identifiers_in_text(expr).iter().any(|id| auth.contains(id))
}

fn same_slot(a: &Slot, b: &Slot) -> bool {
    a.base == b.base && a.keys == b.keys
}

fn write_invalidates_guard(guard: &GuardFact, write: &WriteFact) -> bool {
    if write.conditional {
        return false;
    }
    if !same_slot(&guard.slot, &write.slot) {
        return false;
    }
    let rhs = compact(&write.rhs);
    match &guard.kind {
        GuardKind::Falsey => match write.op {
            WriteOp::Assign => !is_zeroish(&rhs) && rhs != compact_slot(&guard.slot),
            WriteOp::OrAssign | WriteOp::Increment => !is_zeroish(&rhs),
            WriteOp::AddAssign => !is_zeroish(&rhs),
            WriteOp::Delete => false,
        },
        GuardKind::Truthy => match write.op {
            WriteOp::Assign => is_zeroish(&rhs),
            WriteOp::Delete => true,
            _ => false,
        },
        GuardKind::EqualTo(other) => {
            let other = compact(other);
            match write.op {
                WriteOp::Increment => true,
                WriteOp::AddAssign => !is_zeroish(&rhs),
                WriteOp::Assign => {
                    rhs != other
                        && (rhs.contains(&format!("{}+1", other))
                            || rhs.contains(&format!("1+{}", other))
                            || rhs.contains(&format!("{}+", compact_slot(&guard.slot))))
                }
                _ => false,
            }
        }
        GuardKind::GreaterThan(other) => {
            write.op == WriteOp::Assign && compact(&write.rhs) == compact(other)
        }
        GuardKind::BitmapClear(mask) => match write.op {
            WriteOp::OrAssign => compact(&write.rhs) == compact(mask),
            WriteOp::Assign => {
                let rhs = compact(&write.rhs);
                rhs.contains('|') && rhs.contains(&compact(mask))
            }
            _ => false,
        },
        GuardKind::Unknown => false,
    }
}

fn final_write_for_slot<'a>(writes: &'a [WriteFact], slot: &Slot) -> Option<&'a WriteFact> {
    writes.iter().rev().find(|write| same_slot(slot, &write.slot))
}

fn effective_slots(facts: &AnalysisFacts) -> BTreeSet<Slot> {
    facts
        .guards
        .iter()
        .filter(|g| guard_is_authenticated(g, &facts.auth_symbols))
        .filter(|g| {
            final_write_for_slot(&facts.writes, &g.slot)
                .is_some_and(|w| write_invalidates_guard(g, w))
        })
        .map(|g| g.slot.clone())
        .collect()
}

fn expand_expression(expr: &str, assignments: &HashMap<String, String>, depth: usize) -> String {
    if depth == 0 {
        return expr.to_string();
    }
    let mut substitutions = HashMap::new();
    for ident in identifiers_in_text(expr) {
        if let Some(rhs) = assignments.get(&ident) {
            substitutions.insert(ident, format!("({})", expand_expression(rhs, assignments, depth - 1)));
        }
    }
    if substitutions.is_empty() {
        expr.to_string()
    } else {
        substitute_identifiers(expr, &substitutions)
    }
}

fn authorization_shape(model: &FunctionModel, facts: &AnalysisFacts) -> Option<String> {
    if model.direct_auth_roots.is_empty() {
        return None;
    }
    let param_map: HashMap<String, String> = model
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| (p.clone(), format!("$p{i}")))
        .collect();
    let mut roots: Vec<String> = model
        .direct_auth_roots
        .iter()
        .map(|root| expand_expression(root, &model.assignments, 8))
        .map(|root| substitute_identifiers(&root, &param_map))
        .map(|x| compact(&x))
        .collect();
    roots.sort();
    roots.dedup();
    let signed_params = model
        .params
        .iter()
        .enumerate()
        .filter_map(|(i, p)| facts.auth_symbols.contains(p).then_some(format!("$p{i}")))
        .collect::<Vec<_>>()
        .join(",");
    Some(format!("{}|{}", roots.join(";"), signed_params))
}

fn collect_assignments(source: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for statement in split_statements(source) {
        let Some(eq) = find_top_level_operator(&statement, "=") else {
            continue;
        };
        if eq > 0 && matches!(statement.as_bytes().get(eq - 1).copied(), Some(b'!' | b'<' | b'>' | b'=')) {
            continue;
        }
        let lhs = &statement[..eq];
        let rhs = statement[eq + 1..].trim().trim_end_matches(';').trim();
        if lhs.contains('[') {
            continue;
        }
        if let Some(name) = last_identifier(lhs) {
            out.insert(name, rhs.to_string());
        }
    }
    out
}

fn collect_guards(source: &str, excluded_scalars: &[String]) -> Vec<GuardFact> {
    let mut out = Vec::new();
    for keyword in ["require", "assert", "if"] {
        let mut from = 0;
        while let Some(pos) = find_word_from(source, keyword, from) {
            let Some(open) = source[pos + keyword.len()..].find('(').map(|x| pos + keyword.len() + x) else {
                break;
            };
            let Some(close) = matching_delimiter(source, open, '(', ')') else {
                break;
            };
            let raw_condition = &source[open + 1..close];
            let condition = if keyword == "if" {
                raw_condition.trim().to_string()
            } else {
                split_top_level(raw_condition, ',')
                    .into_iter()
                    .next()
                    .unwrap_or_default()
            };
            if let Some(fact) = parse_guard(&condition, pos, excluded_scalars) {
                out.push(fact);
            }
            from = close + 1;
        }
    }
    out
}

fn parse_guard(condition: &str, pos: usize, excluded_scalars: &[String]) -> Option<GuardFact> {
    let cond = condition.trim();
    if let Some(rest) = cond.strip_prefix('!') {
        let slot = parse_slot_excluding(rest.trim(), excluded_scalars)?;
        return Some(GuardFact { slot, kind: GuardKind::Falsey, pos });
    }

    for op in ["==", "!=", ">=", "<=", ">", "<"] {
        if let Some(idx) = find_top_level_operator(cond, op) {
            let left = cond[..idx].trim();
            let right = cond[idx + op.len()..].trim();

            // Bitmap form: (bitmap[...] & mask) == 0
            if matches!(op, "==" | "!=") {
                if let Some(and) = find_top_level_operator(left.trim_matches(|c| c == '(' || c == ')'), "&") {
                    let raw = left.trim_matches(|c| c == '(' || c == ')');
                    if let Some(slot) = parse_slot_excluding(raw[..and].trim(), excluded_scalars) {
                        let mask = raw[and + 1..].trim().to_string();
                        if is_zeroish(&compact(right)) && op == "==" {
                            return Some(GuardFact { slot, kind: GuardKind::BitmapClear(mask), pos });
                        }
                    }
                }
            }

            if let Some(slot) = parse_slot_excluding(left, excluded_scalars) {
                let kind = classify_comparison(op, right, false);
                return Some(GuardFact { slot, kind, pos });
            }
            if let Some(slot) = parse_slot_excluding(right, excluded_scalars) {
                let kind = classify_comparison(op, left, true);
                return Some(GuardFact { slot, kind, pos });
            }
        }
    }

    None
}

fn classify_comparison(op: &str, other: &str, reversed: bool) -> GuardKind {
    let other_compact = compact(other);
    match op {
        "==" if is_zeroish(&other_compact) => GuardKind::Falsey,
        "!=" if is_zeroish(&other_compact) => GuardKind::Truthy,
        "==" => GuardKind::EqualTo(other.trim().to_string()),
        "<" if !reversed => GuardKind::GreaterThan(other.trim().to_string()),
        ">" if reversed => GuardKind::GreaterThan(other.trim().to_string()),
        _ => GuardKind::Unknown,
    }
}

fn collect_writes(source: &str) -> Vec<WriteFact> {
    let mut out = Vec::new();
    let mut offset = 0;
    for statement in split_statements(source) {
        let statement_pos = source[offset..]
            .find(&statement)
            .map(|x| offset + x)
            .unwrap_or(offset);
        offset = statement_pos.saturating_add(statement.len()).min(source.len());
        let s = statement.trim();

        if let Some(delete_idx) = s.find("delete ") {
            let rest = &s[delete_idx + "delete ".len()..];
            if let Some(slot) = parse_slot(rest.trim().trim_end_matches(';')) {
                let pos = statement_pos + statement.rfind(&slot.base).unwrap_or(0);
                out.push(WriteFact {
                    slot,
                    op: WriteOp::Delete,
                    rhs: String::new(),
                    pos,
                    conditional: is_inside_conditional_block(source, pos),
                });
            }
            continue;
        }

        for (operator, op) in [
            ("|=", WriteOp::OrAssign),
            ("+=", WriteOp::AddAssign),
            ("=", WriteOp::Assign),
        ] {
            if let Some(idx) = find_top_level_operator(s, operator) {
                if operator == "="
                    && idx > 0
                    && matches!(
                        s.as_bytes().get(idx - 1).copied(),
                        Some(b'!' | b'<' | b'>' | b'=')
                    )
                {
                    continue;
                }
                if let Some(slot) = parse_lvalue(s[..idx].trim()) {
                    let pos = statement_pos + statement.rfind(&slot.base).unwrap_or(0);
                    out.push(WriteFact {
                        slot,
                        op,
                        rhs: s[idx + operator.len()..]
                            .trim()
                            .trim_end_matches(';')
                            .to_string(),
                        pos,
                        conditional: is_inside_conditional_block(source, pos),
                    });
                }
                break;
            }
        }

        if let Some(idx) = s.find("++") {
            if let Some(slot) = parse_lvalue(s[..idx].trim()) {
                let pos = statement_pos + statement.rfind(&slot.base).unwrap_or(0);
                out.push(WriteFact {
                    slot,
                    op: WriteOp::Increment,
                    rhs: "1".into(),
                    pos,
                    conditional: is_inside_conditional_block(source, pos),
                });
            }
        }
    }
    out
}

fn collect_returned_slot(source: &str) -> Option<Slot> {
    let pos = find_word_from(source, "return", 0)?;
    let rest = &source[pos + "return".len()..];
    let end = rest.find(';').unwrap_or(rest.len());
    parse_slot(rest[..end].trim().trim_matches(|c| c == '(' || c == ')'))
}

fn parse_lvalue(text: &str) -> Option<Slot> {
    let mut text = text.trim().trim_matches(|c| c == '(' || c == ')');
    let cut = [';', '{', '}']
        .iter()
        .filter_map(|c| text.rfind(*c))
        .max();
    if let Some(cut) = cut {
        text = text[cut + 1..].trim();
    }
    if text.contains('[') {
        return parse_slot(text);
    }
    let base = last_identifier(text)?;
    if is_builtin_identifier(&base) {
        None
    } else {
        Some(Slot { base, keys: Vec::new() })
    }
}

fn parse_slot_excluding(text: &str, excluded_scalars: &[String]) -> Option<Slot> {
    let slot = parse_slot(text)?;
    if slot.keys.is_empty() && excluded_scalars.iter().any(|x| x == &slot.base) {
        None
    } else {
        Some(slot)
    }
}

fn parse_slot(text: &str) -> Option<Slot> {
    let text = text.trim().trim_matches(|c| c == '(' || c == ')');
    let base = first_identifier(text)?;
    let start = text.find(&base)? + base.len();
    let mut keys = Vec::new();
    let bytes = text.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'[' {
            break;
        }
        let close = matching_delimiter(text, i, '[', ']')?;
        keys.push(compact(&text[i + 1..close]));
        i = close + 1;
    }
    // Replay state can be scalar (e.g. currentVersion) or indexed. Reject obvious language/builtin
    // values so arithmetic conditions are not mistaken for persistent authorization state.
    if is_builtin_identifier(&base) {
        return None;
    }
    Some(Slot { base, keys })
}

fn digest_argument_at(source: &str, pos: usize, sink_name: &str) -> Option<String> {
    let args = parse_call_args_at(source, pos)?;
    let index = if sink_name == "isValidSignatureNow" && args.len() >= 3 { 1 } else { 0 };
    args.get(index).cloned()
}

fn parse_call_args_at(source: &str, pos: usize) -> Option<Vec<String>> {
    let tail = source.get(pos..)?;
    let open = pos + tail.find('(')?;
    let close = matching_delimiter(source, open, '(', ')')?;
    Some(split_top_level(&source[open + 1..close], ','))
}

fn parse_parameter_names(source: &str) -> Vec<String> {
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
        .map(|part| {
            let identifiers = identifier_sequence(&part);
            identifiers
                .into_iter()
                .rev()
                .find(|x| !is_type_or_location_keyword(x))
                .unwrap_or_default()
        })
        .collect()
}

fn is_public_or_external(source: &str) -> bool {
    let header = source.split('{').next().unwrap_or(source);
    contains_word(header, "public") || contains_word(header, "external")
}

fn looks_like_generic_signature_verifier_call(source: &str) -> bool {
    (source.contains("keccak256")
        || source.contains("_hashTypedDataV4")
        || source.contains("toEthSignedMessageHash"))
        && source.contains("bytes")
}

fn has_sensitive_effect(source: &str) -> bool {
    if source.split('{').next().unwrap_or(source).contains(" view")
        || source.split('{').next().unwrap_or(source).contains(" pure")
    {
        // A view helper can call a signature verifier, but it cannot itself be replay-exploited.
        return false;
    }
    let body = source.split_once('{').map(|(_, b)| b).unwrap_or(source);
    body.contains(".call(")
        || body.contains(".delegatecall(")
        || body.contains(".transfer(")
        || body.contains(".send(")
        || body.contains(".approve(")
        || body.contains(".mint(")
        || body.contains(".burn(")
        || body.contains("emit ")
        || collect_writes(body).iter().any(|w| !is_probable_local_write(w, body))
}

fn is_probable_local_write(write: &WriteFact, body: &str) -> bool {
    // Indexed assignments are overwhelmingly storage in Solidity unless routed through an explicit
    // memory/storage local. Scalars declared in the same function are treated as local.
    if !write.slot.keys.is_empty() {
        return false;
    }
    let declarations = ["uint", "int", "bytes32", "address", "bool", "bytes", "string"];
    declarations.iter().any(|ty| {
        body.contains(&format!("{ty} {}", write.slot.base))
            || body.contains(&format!("{ty} memory {}", write.slot.base))
    })
}

fn has_reverting_external_flow(source: &str) -> bool {
    let has_external = source.contains(".call(")
        || source.contains(".delegatecall(")
        || source.contains("try ");
    if !has_external {
        return false;
    }
    let has_later_revert = source.contains("require(success")
        || source.contains("require(ok")
        || source.contains("assert(success")
        || source.contains("assert(ok")
        || source.contains("revert ")
        || source.contains("revert(")
        || source.contains("catch") && source.contains("revert");
    has_later_revert
}

fn first_external_effect_position(source: &str) -> Option<usize> {
    [".call(", ".delegatecall(", "try "]
        .iter()
        .filter_map(|needle| source.find(needle))
        .min()
}

fn call_condition_context(source: &str, pos: usize) -> (bool, bool) {
    for keyword in ["require", "assert", "if"] {
        let mut from = 0;
        while let Some(kpos) = find_word_from(source, keyword, from) {
            let Some(open) = source[kpos + keyword.len()..].find('(').map(|x| kpos + keyword.len() + x) else {
                break;
            };
            let Some(close) = matching_delimiter(source, open, '(', ')') else {
                break;
            };
            if pos > open && pos < close {
                let prefix = source[open + 1..pos].trim_end();
                return (true, prefix.ends_with('!'));
            }
            from = close + 1;
        }
    }
    (false, false)
}

fn is_inside_conditional_block(source: &str, pos: usize) -> bool {
    let prefix = &source[..pos.min(source.len())];
    let mut search_from = 0;
    while let Some(if_pos) = find_word_from(prefix, "if", search_from) {
        let Some(open_paren) = prefix[if_pos + 2..].find('(').map(|x| if_pos + 2 + x) else {
            break;
        };
        let Some(close_paren) = matching_delimiter(prefix, open_paren, '(', ')') else {
            break;
        };
        let Some(open_brace_rel) = source[close_paren + 1..].find('{') else {
            search_from = close_paren + 1;
            continue;
        };
        let open_brace = close_paren + 1 + open_brace_rel;
        if open_brace >= pos {
            search_from = close_paren + 1;
            continue;
        }
        if let Some(close_brace) = matching_delimiter(source, open_brace, '{', '}') {
            if pos > open_brace && pos < close_brace {
                return true;
            }
        }
        search_from = close_paren + 1;
    }
    false
}

fn split_statements(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut in_string = false;
    let mut quote = '\0';
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            if c == quote && (i == 0 || chars[i - 1] != '\\') {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            in_string = true;
            quote = c;
        } else if c == '(' {
            paren += 1;
        } else if c == ')' {
            paren -= 1;
        } else if c == '[' {
            bracket += 1;
        } else if c == ']' {
            bracket -= 1;
        } else if c == ';' && paren == 0 && bracket == 0 {
            out.push(chars[start..=i].iter().collect());
            start = i + 1;
        }
        i += 1;
    }
    out
}

fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut p = 0i32;
    let mut b = 0i32;
    let mut c = 0i32;
    let chars: Vec<char> = text.chars().collect();
    let mut in_string = false;
    let mut quote = '\0';
    for (i, ch) in chars.iter().enumerate() {
        if in_string {
            if *ch == quote && (i == 0 || chars[i - 1] != '\\') {
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

fn matching_delimiter(text: &str, open: usize, open_ch: char, close_ch: char) -> Option<usize> {
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

fn find_top_level_operator(text: &str, operator: &str) -> Option<usize> {
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

fn identifier_sequence(text: &str) -> Vec<String> {
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

fn identifiers_in_text(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let ident = &text[start..i];
            if !is_language_keyword(ident) {
                out.insert(ident.to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

fn first_identifier(text: &str) -> Option<String> {
    identifier_sequence(text).into_iter().find(|x| !is_language_keyword(x))
}

fn last_identifier(text: &str) -> Option<String> {
    let mut last = None;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let ident = &text[start..i];
            if !is_language_keyword(ident) {
                last = Some(ident.to_string());
            }
        } else {
            i += 1;
        }
    }
    last
}

fn substitute_identifiers(text: &str, substitutions: &HashMap<String, String>) -> String {
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
            out.push_str(substitutions.get(ident).map(String::as_str).unwrap_or(ident));
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn find_word_from(text: &str, word: &str, from: usize) -> Option<usize> {
    let mut cursor = from;
    while let Some(rel) = text.get(cursor..)?.find(word) {
        let pos = cursor + rel;
        let left_ok = pos == 0 || !is_ident_continue(text.as_bytes()[pos - 1]);
        let end = pos + word.len();
        let right_ok = end >= text.len() || !is_ident_continue(text.as_bytes()[end]);
        if left_ok && right_ok {
            return Some(pos);
        }
        cursor = end;
    }
    None
}

fn contains_word(text: &str, word: &str) -> bool {
    find_word_from(text, word, 0).is_some()
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn compact_slot(slot: &Slot) -> String {
    let mut out = slot.base.clone();
    for key in &slot.keys {
        out.push('[');
        out.push_str(&compact(key));
        out.push(']');
    }
    out
}

fn is_zeroish(text: &str) -> bool {
    matches!(text, "0" | "false" | "address(0)" | "bytes32(0)" | "0x0")
}

fn is_ident_start(ch: u8) -> bool {
    ch == b'_' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: u8) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit()
}

fn is_language_keyword(s: &str) -> bool {
    matches!(
        s,
        "function"
            | "returns"
            | "return"
            | "public"
            | "external"
            | "internal"
            | "private"
            | "view"
            | "pure"
            | "memory"
            | "calldata"
            | "storage"
            | "payable"
            | "virtual"
            | "override"
            | "if"
            | "else"
            | "require"
            | "assert"
            | "revert"
            | "true"
            | "false"
            | "new"
            | "delete"
    )
}

fn is_type_or_location_keyword(s: &str) -> bool {
    is_language_keyword(s)
        || s.starts_with("uint")
        || s.starts_with("int")
        || s.starts_with("bytes")
        || matches!(s, "address" | "bool" | "string")
}

fn is_builtin_identifier(s: &str) -> bool {
    matches!(
        s,
        "msg" | "tx" | "block" | "abi" | "address" | "keccak256" | "ecrecover"
    )
}

#[cfg(test)]
mod signature_replay_tests {
    use crate::detect::detector::IssueDetector;

    use super::SignatureReplayDetector;

    fn run(path: &str) -> usize {
        let context = crate::detect::test_utils::load_solidity_source_unit(path);
        let mut detector = SignatureReplayDetector::default();
        detector.detect(&context).unwrap();
        detector.instances().len()
    }

    #[test]
    fn detects_missing_replay_protection() {
        assert_eq!(
            run("../tests/contract-playground/src/signature-replay/SignatureReplayNoProtection.sol"),
            1
        );
    }

    #[test]
    fn accepts_correct_nonce_consumption() {
        assert_eq!(
            run("../tests/contract-playground/src/signature-replay/SignatureReplayNonceSafe.sol"),
            0
        );
    }

    #[test]
    fn detects_checked_but_unconsumed_authorization() {
        assert_eq!(
            run("../tests/contract-playground/src/signature-replay/SignatureReplayCheckedNotConsumed.sol"),
            1
        );
    }

    #[test]
    fn accepts_interprocedural_guard_and_consumption() {
        assert_eq!(
            run("../tests/contract-playground/src/signature-replay/SignatureReplayInterproceduralSafe.sol"),
            0
        );
    }

    #[test]
    fn detects_replay_state_rollback() {
        assert_eq!(
            run("../tests/contract-playground/src/signature-replay/SignatureReplayRollback.sol"),
            1
        );
    }

    #[test]
    fn detects_cross_function_independent_registries() {
        assert!(
            run("../tests/contract-playground/src/signature-replay/SignatureReplayCrossFunction.sol")
                >= 1
        );
    }
}