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

/// Detects stale or attacker-adjustable signature authorizations caused by missing,
/// unauthenticated, or ineffective freshness controls.
///
/// Aderyn v0.6.8 does not expose a detector-facing SSA/CFG abstraction.  This detector therefore
/// uses the Solidity AST for function boundaries and internal call edges, and a bounded,
/// Solidity-aware source pass for digest dependencies and freshness predicates.  The analysis is
/// intentionally conservative about "missing deadline" findings: a signature is not considered
/// vulnerable merely because it has indefinite validity.  Absence findings require independent
/// evidence that the authorization is time-sensitive and are suppressed when an authenticated,
/// revocable authorization generation/version is present.
#[derive(Default)]
pub struct SignatureFreshnessDetector {
    found_instances: BTreeMap<(String, usize, String), NodeID>,
}

const MAX_CALL_DEPTH: usize = 5;
const ABSENCE_CONFIDENCE_THRESHOLD: i32 = 6;

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

#[derive(Debug, Clone, Default)]
struct Parameter {
    ty: String,
    name: String,
}

#[derive(Debug, Clone, Default)]
struct FunctionSignature {
    name: String,
    params: Vec<Parameter>,
    is_public: bool,
    is_external: bool,
    is_view: bool,
    is_pure: bool,
    has_body: bool,
}

impl FunctionSignature {
    fn is_entry_point(&self) -> bool {
        self.is_public || self.is_external
    }

    fn is_read_only(&self) -> bool {
        self.is_view || self.is_pure
    }
}

#[derive(Debug, Clone)]
struct CallSite {
    callee: NodeID,
    args: Vec<String>,
}

#[derive(Debug, Clone)]
struct AssignmentFact {
    lhs: String,
    rhs: String,
}

#[derive(Debug, Clone)]
struct FunctionModel {
    id: NodeID,
    scope: NodeID,
    source: String,
    sig: FunctionSignature,
    calls: Vec<CallSite>,
    assignments: HashMap<String, String>,
    assignment_facts: Vec<AssignmentFact>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AuthSummary {
    signature_gated: bool,
    authenticated_names: BTreeSet<String>,
    authenticated_exprs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FreshnessSemantic {
    UpperTime,
    LowerTime,
    PointTime,
    PointTimeMillis,
    UpperBlock,
    LowerBlock,
    Round,
    Epoch,
    InferredUpperTime,
    InferredLowerTime,
    InferredUpperBlock,
    InferredLowerBlock,
}

impl FreshnessSemantic {
    fn is_staleness_limiting(self) -> bool {
        matches!(
            self,
            FreshnessSemantic::UpperTime
                | FreshnessSemantic::PointTime
                | FreshnessSemantic::PointTimeMillis
                | FreshnessSemantic::UpperBlock
                | FreshnessSemantic::Round
                | FreshnessSemantic::Epoch
                | FreshnessSemantic::InferredUpperTime
                | FreshnessSemantic::InferredUpperBlock
        )
    }

    fn is_upper_bound(self) -> bool {
        matches!(
            self,
            FreshnessSemantic::UpperTime
                | FreshnessSemantic::UpperBlock
                | FreshnessSemantic::InferredUpperTime
                | FreshnessSemantic::InferredUpperBlock
        )
    }

    fn is_lower_bound(self) -> bool {
        matches!(
            self,
            FreshnessSemantic::LowerTime
                | FreshnessSemantic::LowerBlock
                | FreshnessSemantic::InferredLowerTime
                | FreshnessSemantic::InferredLowerBlock
        )
    }
}

#[derive(Debug, Clone)]
struct FreshnessCandidate {
    expr: String,
    names: BTreeSet<String>,
    semantic: FreshnessSemantic,
}

#[derive(Debug, Clone, Default)]
struct Enforcement {
    upper_bound: bool,
    lower_bound: bool,
    age_bound: bool,
    monotonic: bool,
    shape_only: bool,
    unit_mismatch: bool,
}

impl Enforcement {
    fn meaningful_for(&self, semantic: FreshnessSemantic) -> bool {
        if self.unit_mismatch {
            return false;
        }
        match semantic {
            FreshnessSemantic::UpperTime
            | FreshnessSemantic::UpperBlock
            | FreshnessSemantic::InferredUpperTime
            | FreshnessSemantic::InferredUpperBlock => self.upper_bound || self.age_bound,
            FreshnessSemantic::PointTime | FreshnessSemantic::PointTimeMillis => {
                self.age_bound || self.monotonic
            }
            FreshnessSemantic::Round | FreshnessSemantic::Epoch => self.monotonic,
            FreshnessSemantic::LowerTime
            | FreshnessSemantic::LowerBlock
            | FreshnessSemantic::InferredLowerTime
            | FreshnessSemantic::InferredLowerBlock => self.lower_bound,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindingReason {
    MissingMeaningfulFreshness,
    FreshnessNotAuthenticated,
    AuthenticatedFreshnessNotEnforced,
}

impl IssueDetector for SignatureFreshnessDetector {
    fn detect(&mut self, context: &WorkspaceContext) -> Result<bool, Box<dyn Error>> {
        let models = build_models(context);
        if models.is_empty() {
            return Ok(false);
        }

        let auth = build_auth_summaries(&models);
        let mut vulnerable: BTreeMap<NodeID, FindingReason> = BTreeMap::new();

        for model in models.values() {
            if !model.sig.is_entry_point() || model.sig.is_read_only() || !model.sig.has_body {
                continue;
            }
            let Some(summary) = auth.get(&model.id) else {
                continue;
            };
            if !summary.signature_gated || !has_sensitive_effect(model) {
                continue;
            }

            if let Some(reason) = analyze_freshness(model, &models, summary) {
                vulnerable.insert(model.id, reason);
            }
        }

        for function in context.function_definitions() {
            if vulnerable.contains_key(&function.id) {
                capture!(self, context, function);
            }
        }

        Ok(!self.found_instances.is_empty())
    }

    fn severity(&self) -> IssueSeverity {
        IssueSeverity::High
    }

    fn title(&self) -> String {
        "Signature Freshness Validation Missing or Ineffective".to_string()
    }

    fn description(&self) -> String {
        String::from(concat!(
            "A signature-authorized operation appears to lack an effective freshness invariant. ",
            "Freshness is distinct from replay protection: a nonce or consumed authorization answers ",
            "whether an authorization was already used, while freshness answers whether it is still ",
            "appropriate to execute now. Verify that temporal, block-window, round, epoch, or report-", 
            "age data is authenticated by the signed digest and is actually enforced before the ",
            "security-sensitive effect. For timestamped reports, enforce a bounded age and/or monotonic ",
            "progression. Do not add a deadline mechanically when indefinite validity is an intentional, ",
            "revocable part of the authorization design."
        ))
    }

    fn instances(&self) -> BTreeMap<(String, usize, String), NodeID> {
        self.found_instances.clone()
    }

    fn name(&self) -> String {
        format!("{}", IssueDetectorNamePool::SignatureFreshness)
    }
}

fn analyze_freshness(
    model: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    auth: &AuthSummary,
) -> Option<FindingReason> {
    let predicates = collect_effective_predicates(model.id, models, MAX_CALL_DEPTH);
    let assignments = collect_effective_assignments(model.id, models, MAX_CALL_DEPTH);
    let candidates = collect_candidates(model, auth, &predicates);

    let mut has_authenticated_effective_staleness_limit = false;
    let mut has_unauthenticated_freshness_check = false;
    let mut has_authenticated_ineffective_staleness_signal = false;
    let mut has_any_upper_semantic = false;

    for candidate in &candidates {
        if candidate.semantic.is_upper_bound() {
            has_any_upper_semantic = true;
        }

        let authenticated = candidate_is_authenticated(candidate, model, auth);
        let enforcement = evaluate_enforcement(candidate, &predicates, &assignments);
        let meaningful = enforcement.meaningful_for(candidate.semantic);

        if authenticated && meaningful && candidate.semantic.is_staleness_limiting() {
            has_authenticated_effective_staleness_limit = true;
        }

        // A runtime freshness predicate that the signer did not authenticate is attacker-adjustable.
        if !authenticated && candidate_is_checked(candidate, &predicates) {
            if meaningful || enforcement.shape_only || candidate.semantic.is_staleness_limiting() {
                has_unauthenticated_freshness_check = true;
            }
        }

        // Signed deadline/timestamp/round/epoch data that is not effectively enforced is stale-data risk.
        if authenticated && candidate.semantic.is_staleness_limiting() && !meaningful {
            has_authenticated_ineffective_staleness_signal = true;
        }
    }

    // A signed lower-bound-only window (e.g. validAfter with no validBefore/age/monotonic control)
    // does not constrain how late the authorization may be executed.
    if !has_authenticated_effective_staleness_limit
        && !has_any_upper_semantic
        && candidates.iter().any(|candidate| {
            candidate_is_authenticated(candidate, model, auth)
                && candidate.semantic.is_lower_bound()
                && evaluate_enforcement(candidate, &predicates, &assignments)
                    .meaningful_for(candidate.semantic)
        })
    {
        has_authenticated_ineffective_staleness_signal = true;
    }

    if has_unauthenticated_freshness_check {
        return Some(FindingReason::FreshnessNotAuthenticated);
    }

    if has_authenticated_ineffective_staleness_signal {
        return Some(FindingReason::AuthenticatedFreshnessNotEnforced);
    }

    if has_authenticated_effective_staleness_limit {
        return None;
    }

    // Intentionally indefinite authorizations can be safe.  Suppress absence findings when the
    // signed authorization contains an explicit revocable authorization generation/version.
    if has_authenticated_revocation_generation(auth) {
        return None;
    }

    let signed_forever_sentinel = auth
        .authenticated_exprs
        .iter()
        .any(|expr| contains_forever_sentinel(expr));

    let confidence = absence_context_confidence(model, auth, &predicates);
    if signed_forever_sentinel && confidence >= ABSENCE_CONFIDENCE_THRESHOLD - 1 {
        return Some(FindingReason::MissingMeaningfulFreshness);
    }

    if candidates.is_empty() && confidence >= ABSENCE_CONFIDENCE_THRESHOLD {
        return Some(FindingReason::MissingMeaningfulFreshness);
    }

    None
}

fn build_models(context: &WorkspaceContext) -> BTreeMap<NodeID, FunctionModel> {
    // Aderyn v0.6.8 returns Vec<&FunctionDefinition>, not an Iterator.  Keep `.into_iter()` here;
    // this is one of the API details that differs from examples written against other revisions.
    let function_spans: Vec<(NodeID, SrcSpan)> = context
        .function_definitions()
        .into_iter()
        .filter_map(|f| SrcSpan::parse(&f.src).map(|span| (f.id, span)))
        .collect();
    let function_ids: HashSet<NodeID> = function_spans.iter().map(|(id, _)| *id).collect();

    let mut call_sites_by_function: HashMap<NodeID, Vec<CallSite>> = HashMap::new();
    for identifier in context.identifiers() {
        // In the user's v0.6.8 tree `referenced_declaration` is a field, not a method.
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
        let Some(function) = context
            .function_definitions()
            .into_iter()
            .find(|f| f.id == caller)
        else {
            continue;
        };
        let source = function.peek(context).unwrap_or_default();
        let local_pos = node_span.start.saturating_sub(fspan.start);
        let args = parse_call_args_at(&source, local_pos).unwrap_or_default();
        call_sites_by_function
            .entry(caller)
            .or_default()
            .push(CallSite { callee, args });
    }

    let mut models = BTreeMap::new();
    for function in context.function_definitions() {
        let source = function.peek(context).unwrap_or_default();
        let sig = parse_function_signature(&source);
        let assignment_facts = collect_assignment_facts(&source);
        let assignments = assignment_facts
            .iter()
            .filter_map(|fact| simple_identifier(&fact.lhs).map(|name| (name, fact.rhs.clone())))
            .collect();
        models.insert(
            function.id,
            FunctionModel {
                id: function.id,
                scope: function.scope,
                source,
                sig,
                calls: call_sites_by_function.remove(&function.id).unwrap_or_default(),
                assignments,
                assignment_facts,
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

fn build_auth_summaries(models: &BTreeMap<NodeID, FunctionModel>) -> BTreeMap<NodeID, AuthSummary> {
    let mut summaries = BTreeMap::new();
    for model in models.values() {
        summaries.insert(model.id, direct_auth_summary(model));
    }

    // Bounded fixed point: propagate digest dependencies through internal verification wrappers.
    for _ in 0..(MAX_CALL_DEPTH + 2) {
        let previous = summaries.clone();
        let mut changed = false;

        for model in models.values() {
            let mut next = previous.get(&model.id).cloned().unwrap_or_default();
            for call in &model.calls {
                let Some(callee) = models.get(&call.callee) else {
                    continue;
                };
                let Some(callee_summary) = previous.get(&call.callee) else {
                    continue;
                };
                if !callee_summary.signature_gated {
                    continue;
                }
                next.signature_gated = true;

                for (index, param) in callee.sig.params.iter().enumerate() {
                    if !callee_summary.authenticated_names.contains(&param.name) {
                        continue;
                    }
                    let Some(arg) = call.args.get(index) else {
                        continue;
                    };
                    let expanded = expand_expression(arg, &model.assignments, 8);
                    next.authenticated_names.extend(identifiers_in_text(&expanded));
                    next.authenticated_exprs.insert(expanded);
                }
            }

            if previous.get(&model.id) != Some(&next) {
                summaries.insert(model.id, next);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    summaries
}

fn direct_auth_summary(model: &FunctionModel) -> AuthSummary {
    let mut summary = AuthSummary::default();
    for sink in collect_signature_sinks(model) {
        summary.signature_gated = true;
        let expanded = expand_expression(&sink, &model.assignments, 8);
        summary
            .authenticated_names
            .extend(identifiers_in_text(&expanded));
        summary.authenticated_exprs.insert(expanded);
    }
    summary
}

/// Return the hash/digest expressions that flow into recognized signature-verification sinks.
fn collect_signature_sinks(model: &FunctionModel) -> Vec<String> {
    let mut out = Vec::new();
    let source = strip_comments(&model.source);

    // Built-in ecrecover(hash, v, r, s).
    for args in find_calls_named(&source, "ecrecover") {
        if args.len() == 4 {
            out.push(args[0].clone());
        }
    }

    // Common ECDSA / SignatureChecker / ERC-1271 / verifier shapes.
    for name in [
        "tryRecover",
        "recover",
        "isValidSignatureNow",
        "isValidSignature",
        "verify",
    ] {
        for args in find_calls_named(&source, name) {
            if args.len() < 2 {
                continue;
            }

            let (hash_index, signature_index) = match name {
                "isValidSignatureNow" if args.len() >= 3 => (1usize, 2usize),
                "verify" if args.len() >= 3 => (1usize, 2usize),
                _ => (0usize, 1usize),
            };
            let Some(hash_expr) = args.get(hash_index) else {
                continue;
            };
            let Some(signature_expr) = args.get(signature_index) else {
                continue;
            };
            if signature_expression_is_plausible(signature_expr, &model.sig) {
                out.push(hash_expr.clone());
            }
        }
    }

    out
}

fn signature_expression_is_plausible(expr: &str, sig: &FunctionSignature) -> bool {
    let deps = identifiers_in_text(expr);
    if deps.iter().any(|name| signatureish_name(name)) {
        return true;
    }
    sig.params.iter().any(|param| {
        deps.contains(&param.name)
            && dynamic_bytes_type(&param.ty)
    })
}

fn dynamic_bytes_type(ty: &str) -> bool {
    let t = ty.replace(' ', "").to_ascii_lowercase();
    t == "bytes" || t.starts_with("bytescalldata") || t.starts_with("bytesmemory")
}

fn signatureish_name(name: &str) -> bool {
    let n = compact_name(name);
    n == "sig" || n.contains("signature") || n.ends_with("sig")
}

fn collect_candidates(
    model: &FunctionModel,
    auth: &AuthSummary,
    predicates: &[String],
) -> Vec<FreshnessCandidate> {
    let mut candidates = Vec::new();

    for param in &model.sig.params {
        if let Some(semantic) = freshness_semantic_from_name(&param.name) {
            candidates.push(FreshnessCandidate {
                expr: param.name.clone(),
                names: BTreeSet::from([param.name.clone()]),
                semantic,
            });
        }
    }

    // Signed fields may be local aliases rather than parameters.
    for name in &auth.authenticated_names {
        if let Some(semantic) = freshness_semantic_from_name(name) {
            candidates.push(FreshnessCandidate {
                expr: name.clone(),
                names: BTreeSet::from([name.clone()]),
                semantic,
            });
        }
    }

    // A value compared with block.timestamp/block.number is freshness data even when its identifier
    // does not use a conventional deadline/timestamp name.
    for predicate in predicates {
        candidates.extend(infer_candidates_from_predicate(predicate));
    }

    dedupe_candidates(candidates)
}

fn dedupe_candidates(candidates: Vec<FreshnessCandidate>) -> Vec<FreshnessCandidate> {
    let mut seen: BTreeSet<(String, FreshnessSemantic)> = BTreeSet::new();
    let mut out = Vec::new();
    for mut candidate in candidates {
        if candidate.names.is_empty() {
            candidate.names = identifiers_in_text(&candidate.expr);
        }
        let key_name = candidate
            .names
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| canonical_expr(&candidate.expr));
        if seen.insert((key_name, candidate.semantic)) {
            out.push(candidate);
        }
    }
    out
}

fn freshness_semantic_from_name(name: &str) -> Option<FreshnessSemantic> {
    let n = compact_name(name);
    if n.is_empty() {
        return None;
    }

    let is_block = n.contains("block");
    let upper = n.contains("deadline")
        || n.contains("expiry")
        || n.contains("expiration")
        || n.contains("expiresat")
        || n.contains("validbefore")
        || n.contains("validuntil")
        || n.contains("validthrough")
        || n.contains("notafter")
        || n.contains("endtime")
        || n.contains("endtimestamp")
        || n.contains("lastvalid");
    if upper {
        return Some(if is_block {
            FreshnessSemantic::UpperBlock
        } else {
            FreshnessSemantic::UpperTime
        });
    }

    let lower = n.contains("validafter")
        || n.contains("validfrom")
        || n.contains("notbefore")
        || n.contains("starttime")
        || n.contains("starttimestamp")
        || n.contains("firstvalid");
    if lower {
        return Some(if is_block {
            FreshnessSemantic::LowerBlock
        } else {
            FreshnessSemantic::LowerTime
        });
    }

    if n.contains("round") {
        return Some(FreshnessSemantic::Round);
    }
    if n.contains("epoch") {
        return Some(FreshnessSemantic::Epoch);
    }

    let timestamp_like = n.contains("timestamp")
        || n.contains("issuedat")
        || n.contains("publishtime")
        || n.contains("publishedat")
        || n.contains("reporttime")
        || n.contains("observedat")
        || n.contains("signedat")
        || n.contains("updatedat")
        || n.contains("createdat");
    if timestamp_like {
        let milliseconds = n.ends_with("ms")
            || n.contains("millis")
            || n.contains("milliseconds");
        return Some(if milliseconds {
            FreshnessSemantic::PointTimeMillis
        } else {
            FreshnessSemantic::PointTime
        });
    }

    None
}

fn infer_candidates_from_predicate(predicate: &str) -> Vec<FreshnessCandidate> {
    let mut out = Vec::new();
    let Some((lhs, op, rhs)) = split_top_level_comparison(predicate) else {
        return out;
    };
    let lhs_time = contains_block_timestamp(&lhs);
    let rhs_time = contains_block_timestamp(&rhs);
    let lhs_block = contains_block_number(&lhs);
    let rhs_block = contains_block_number(&rhs);

    if lhs_time ^ rhs_time {
        let (candidate_expr, semantic) = if lhs_time {
            let sem = match op.as_str() {
                "<" | "<=" => FreshnessSemantic::InferredUpperTime,
                ">" | ">=" => FreshnessSemantic::InferredLowerTime,
                _ => return out,
            };
            (rhs.clone(), sem)
        } else {
            let sem = match op.as_str() {
                ">" | ">=" => FreshnessSemantic::InferredUpperTime,
                "<" | "<=" => FreshnessSemantic::InferredLowerTime,
                _ => return out,
            };
            (lhs.clone(), sem)
        };
        let names = identifiers_in_text(&candidate_expr)
            .into_iter()
            .filter(|name| name != "block" && name != "timestamp")
            .collect();
        out.push(FreshnessCandidate {
            expr: candidate_expr,
            names,
            semantic,
        });
    }

    if lhs_block ^ rhs_block {
        let (candidate_expr, semantic) = if lhs_block {
            let sem = match op.as_str() {
                "<" | "<=" => FreshnessSemantic::InferredUpperBlock,
                ">" | ">=" => FreshnessSemantic::InferredLowerBlock,
                _ => return out,
            };
            (rhs, sem)
        } else {
            let sem = match op.as_str() {
                ">" | ">=" => FreshnessSemantic::InferredUpperBlock,
                "<" | "<=" => FreshnessSemantic::InferredLowerBlock,
                _ => return out,
            };
            (lhs, sem)
        };
        let names = identifiers_in_text(&candidate_expr)
            .into_iter()
            .filter(|name| name != "block" && name != "number")
            .collect();
        out.push(FreshnessCandidate {
            expr: candidate_expr,
            names,
            semantic,
        });
    }

    out
}

fn candidate_is_authenticated(
    candidate: &FreshnessCandidate,
    model: &FunctionModel,
    auth: &AuthSummary,
) -> bool {
    if !candidate.names.is_disjoint(&auth.authenticated_names) {
        return true;
    }
    let expanded = expand_expression(&candidate.expr, &model.assignments, 8);
    let deps = identifiers_in_text(&expanded);
    !deps.is_disjoint(&auth.authenticated_names)
}

fn candidate_is_checked(candidate: &FreshnessCandidate, predicates: &[String]) -> bool {
    predicates
        .iter()
        .any(|predicate| expression_mentions_candidate(predicate, candidate))
}

fn evaluate_enforcement(
    candidate: &FreshnessCandidate,
    predicates: &[String],
    assignments: &[AssignmentFact],
) -> Enforcement {
    let mut result = Enforcement::default();

    for predicate in predicates {
        if !expression_mentions_candidate(predicate, candidate) {
            continue;
        }
        let compact = canonical_expr(predicate);

        if candidate.semantic == FreshnessSemantic::PointTimeMillis
            && (contains_block_timestamp(predicate))
            && !contains_millisecond_normalization(&compact)
        {
            result.unit_mismatch = true;
        }

        let Some((lhs, op, rhs)) = split_top_level_comparison(predicate) else {
            continue;
        };

        let lhs_has_candidate = expression_mentions_candidate(&lhs, candidate);
        let rhs_has_candidate = expression_mentions_candidate(&rhs, candidate);
        let lhs_time = contains_block_timestamp(&lhs);
        let rhs_time = contains_block_timestamp(&rhs);
        let lhs_block = contains_block_number(&lhs);
        let rhs_block = contains_block_number(&rhs);

        // Age windows, e.g. block.timestamp - issuedAt <= MAX_AGE or
        // block.timestamp <= issuedAt + MAX_AGE.
        if lhs_has_candidate && lhs_time && !rhs_time {
            if matches!(op.as_str(), "<" | "<=") {
                result.age_bound = true;
            }
        }
        if rhs_has_candidate && rhs_time && !lhs_time {
            if matches!(op.as_str(), ">" | ">=") {
                result.age_bound = true;
            }
        }

        if lhs_time && rhs_has_candidate && !rhs_time {
            match op.as_str() {
                "<" | "<=" => result.upper_bound = true,
                ">" | ">=" => result.lower_bound = true,
                _ => {}
            }
            if matches!(candidate.semantic, FreshnessSemantic::PointTime | FreshnessSemantic::PointTimeMillis)
                && rhs.contains('+')
            {
                result.age_bound = true;
            }
        } else if rhs_time && lhs_has_candidate && !lhs_time {
            match op.as_str() {
                ">" | ">=" => result.upper_bound = true,
                "<" | "<=" => result.lower_bound = true,
                _ => {}
            }
            if matches!(candidate.semantic, FreshnessSemantic::PointTime | FreshnessSemantic::PointTimeMillis)
                && lhs.contains('+')
            {
                result.age_bound = true;
            }
        }

        if lhs_block && rhs_has_candidate && !rhs_block {
            match op.as_str() {
                "<" | "<=" => result.upper_bound = true,
                ">" | ">=" => result.lower_bound = true,
                _ => {}
            }
        } else if rhs_block && lhs_has_candidate && !lhs_block {
            match op.as_str() {
                ">" | ">=" => result.upper_bound = true,
                "<" | "<=" => result.lower_bound = true,
                _ => {}
            }
        }

        if is_shape_only_comparison(&lhs, &op, &rhs, candidate) {
            result.shape_only = true;
        }

        // Monotonic freshness: signed round/epoch/timestamp must advance a persistent slot.
        if !lhs_time && !rhs_time && !lhs_block && !rhs_block {
            let monotonic_state_expr = if lhs_has_candidate && matches!(op.as_str(), ">" | ">=") {
                Some(rhs.as_str())
            } else if rhs_has_candidate && matches!(op.as_str(), "<" | "<=") {
                Some(lhs.as_str())
            } else {
                None
            };
            if let Some(state_expr) = monotonic_state_expr {
                if looks_like_state_expression(state_expr)
                    && assignment_updates_state_from_candidate(state_expr, candidate, assignments)
                {
                    result.monotonic = true;
                }
            }
        }
    }

    result
}

fn expression_mentions_candidate(expr: &str, candidate: &FreshnessCandidate) -> bool {
    let ids = identifiers_in_text(expr);
    !ids.is_disjoint(&candidate.names)
}

fn contains_millisecond_normalization(compact: &str) -> bool {
    compact.contains("/1000")
        || compact.contains("*1000")
        || compact.contains("1000*")
        || compact.contains("1e3")
        || compact.contains("10**3")
}

fn is_shape_only_comparison(
    lhs: &str,
    op: &str,
    rhs: &str,
    candidate: &FreshnessCandidate,
) -> bool {
    let lhs_c = expression_mentions_candidate(lhs, candidate);
    let rhs_c = expression_mentions_candidate(rhs, candidate);
    if lhs_c == rhs_c {
        return false;
    }
    let other = if lhs_c { rhs } else { lhs };
    let o = canonical_expr(other);
    let literal_small = o == "0" || o == "1" || o == "0x0";
    literal_small && matches!(op, "!=" | ">" | ">=" | "<" | "<=")
}

fn looks_like_state_expression(expr: &str) -> bool {
    let compact = canonical_expr(expr);
    if compact.is_empty() || compact.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    compact.contains('[')
        || compact.contains('.')
        || identifiers_in_text(expr).len() == 1
}

fn assignment_updates_state_from_candidate(
    state_expr: &str,
    candidate: &FreshnessCandidate,
    assignments: &[AssignmentFact],
) -> bool {
    let wanted = canonical_expr(state_expr);
    assignments.iter().any(|fact| {
        let lhs = canonical_expr(&fact.lhs);
        (lhs == wanted || lhs.ends_with(&wanted) || wanted.ends_with(&lhs))
            && expression_mentions_candidate(&fact.rhs, candidate)
    })
}

fn has_authenticated_revocation_generation(auth: &AuthSummary) -> bool {
    auth.authenticated_names.iter().any(|name| {
        let n = compact_name(name);
        let generation = n.contains("version") || n.contains("generation") || n.contains("revision");
        let authorization = n.contains("authorization")
            || n.contains("auth")
            || n.contains("revocation")
            || n.contains("invalidate")
            || n.contains("keyversion");
        generation && authorization
    })
}

fn contains_forever_sentinel(expr: &str) -> bool {
    let e = canonical_expr(expr).to_ascii_lowercase();
    e.contains("type(uint256).max")
        || e.contains("type(uint64).max")
        || e.contains("type(uint48).max")
        || e.contains("uint256.max")
}

fn absence_context_confidence(
    model: &FunctionModel,
    auth: &AuthSummary,
    predicates: &[String],
) -> i32 {
    let s = model.source.to_ascii_lowercase();
    let mut score = 0i32;

    // Independent evidence that the function is a signature authorization.
    if auth.signature_gated {
        score += 1;
    }
    if has_sensitive_effect(model) {
        score += 2;
    }

    // Standards-/domain-semantic signals.  These are generic security concepts, not benchmark IDs
    // or exact contract names.  Several weaker signals are required before an absence finding fires.
    if s.contains("allowance[") && s.contains("spender") && s.contains("owner") {
        score += 4; // permit-like approval
    }
    if s.contains("transferwithauthorization") || s.contains("receivewithauthorization") {
        score += 5;
    }
    if s.contains("oracle") && s.contains("price") {
        score += 4;
    } else if s.contains("price") && (s.contains("attest") || s.contains("quote")) {
        score += 3;
    }
    if s.contains("order") || s.contains("rfq") || s.contains("quoteid") {
        score += 3;
    }
    if s.contains("session") && (s.contains("key") || s.contains("limit")) {
        score += 3;
    }
    if s.contains("subscription") || (s.contains("subscriber") && s.contains("merchant")) {
        score += 3;
    }
    if s.contains("keeper") || s.contains("upkeep") {
        score += 3;
    }
    if s.contains("proposal") || s.contains("vote") || s.contains("governance") {
        score += 2;
    }
    if s.contains("bridge") || (s.contains("validator") && s.contains("messageid")) {
        score += 2;
    }
    if s.contains("voucher") || (s.contains("issuer") && s.contains("tokenid")) {
        score += 2;
    }
    if s.contains("claimid") || (s.contains("claim") && s.contains("reward")) {
        score += 2;
    }
    if s.contains("withdraw") || (s.contains("credit[") && s.contains("recipient")) {
        score += 2;
    }
    if s.contains("target.call") || s.contains("target.call{") {
        score += 2;
    }
    if s.contains("delegate") && (s.contains("approval") || s.contains("approved")) {
        score += 2;
    }
    if s.contains("balances[") && s.contains("from") && s.contains("to") {
        score += 2;
    }

    // A freshness-related reject predicate elsewhere in the wrapper is an additional signal that
    // time/round semantics matter, even if the particular value is not authenticated.
    if predicates.iter().any(|predicate| {
        contains_block_timestamp(predicate)
            || contains_block_number(predicate)
            || identifiers_in_text(predicate)
                .iter()
                .any(|name| freshness_semantic_from_name(name).is_some())
    }) {
        score += 1;
    }

    score
}

fn has_sensitive_effect(model: &FunctionModel) -> bool {
    if model.sig.is_read_only() {
        return false;
    }
    let source = strip_comments(&model.source);
    let body = function_body(&source).unwrap_or(source.as_str());
    let compact = canonical_expr(body);

    if compact.contains(".call(")
        || compact.contains(".call{")
        || compact.contains(".delegatecall(")
        || compact.contains(".transfer(")
        || compact.contains(".send(")
        || compact.contains("++")
        || compact.contains("--")
        || compact.contains("+=")
        || compact.contains("-=")
        || compact.contains("|=")
        || compact.contains("&=")
    {
        return true;
    }

    model.assignment_facts.iter().any(|fact| {
        let lhs = fact.lhs.trim();
        lhs.contains('[')
            || lhs.contains('.')
            || !is_local_declaration_lhs(lhs)
    })
}

fn is_local_declaration_lhs(lhs: &str) -> bool {
    let l = lhs.trim().to_ascii_lowercase();
    [
        "address ", "uint", "int", "bytes", "bool ", "string ", "mapping", "var ",
    ]
    .iter()
    .any(|prefix| l.starts_with(prefix))
}

fn collect_effective_predicates(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = BTreeSet::new();
    collect_predicates_recursive(root, models, depth, &HashMap::new(), &mut stack, &mut out);
    out
}

fn collect_predicates_recursive(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
    substitutions: &HashMap<String, String>,
    stack: &mut BTreeSet<NodeID>,
    out: &mut Vec<String>,
) {
    if depth == 0 || !stack.insert(id) {
        return;
    }
    let Some(model) = models.get(&id) else {
        stack.remove(&id);
        return;
    };

    for predicate in collect_required_predicates(&model.source) {
        out.push(substitute_identifiers(&predicate, substitutions));
    }

    for call in &model.calls {
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        let mut child_substitutions = HashMap::new();
        for (index, param) in callee.sig.params.iter().enumerate() {
            if let Some(arg) = call.args.get(index) {
                child_substitutions.insert(
                    param.name.clone(),
                    substitute_identifiers(arg, substitutions),
                );
            }
        }
        collect_predicates_recursive(
            call.callee,
            models,
            depth - 1,
            &child_substitutions,
            stack,
            out,
        );
    }

    stack.remove(&id);
}

fn collect_effective_assignments(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> Vec<AssignmentFact> {
    let mut out = Vec::new();
    let mut stack = BTreeSet::new();
    collect_assignments_recursive(root, models, depth, &HashMap::new(), &mut stack, &mut out);
    out
}

fn collect_assignments_recursive(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
    substitutions: &HashMap<String, String>,
    stack: &mut BTreeSet<NodeID>,
    out: &mut Vec<AssignmentFact>,
) {
    if depth == 0 || !stack.insert(id) {
        return;
    }
    let Some(model) = models.get(&id) else {
        stack.remove(&id);
        return;
    };

    for fact in &model.assignment_facts {
        out.push(AssignmentFact {
            lhs: substitute_identifiers(&fact.lhs, substitutions),
            rhs: substitute_identifiers(&fact.rhs, substitutions),
        });
    }

    for call in &model.calls {
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        let mut child_substitutions = HashMap::new();
        for (index, param) in callee.sig.params.iter().enumerate() {
            if let Some(arg) = call.args.get(index) {
                child_substitutions.insert(
                    param.name.clone(),
                    substitute_identifiers(arg, substitutions),
                );
            }
        }
        collect_assignments_recursive(
            call.callee,
            models,
            depth - 1,
            &child_substitutions,
            stack,
            out,
        );
    }

    stack.remove(&id);
}

fn collect_required_predicates(source: &str) -> Vec<String> {
    let source = strip_comments(source);
    let mut out = Vec::new();

    for name in ["require", "assert"] {
        for args in find_calls_named(&source, name) {
            if let Some(first) = args.first() {
                out.push(strip_outer_parens(first.trim()).to_string());
            }
        }
    }

    // Reject branches also establish a required predicate:
    // `if (!(fresh)) return false;` => fresh
    // `if (expired) revert ...;`    => !expired
    let bytes = source.as_bytes();
    let mut pos = 0usize;
    while let Some(rel) = find_word_from(&source, "if", pos) {
        let if_pos = rel;
        let Some(open) = source[if_pos + 2..].find('(').map(|x| if_pos + 2 + x) else {
            break;
        };
        let Some(close) = matching_delimiter(&source, open, '(', ')') else {
            break;
        };
        let condition = source[open + 1..close].trim();
        let suffix_end = (close + 180).min(bytes.len());
        let suffix = source[close + 1..suffix_end].to_ascii_lowercase();
        let rejects = suffix.contains("return false")
            || suffix.contains("revert")
            || suffix.contains("return 0xffffffff")
            || suffix.contains("return bytes4(0)");
        if rejects {
            out.push(invert_predicate(condition));
        }
        pos = close.saturating_add(1);
    }

    out
}

fn invert_predicate(condition: &str) -> String {
    let c = strip_outer_parens(condition.trim());
    if let Some(rest) = c.strip_prefix('!') {
        return strip_outer_parens(rest.trim()).to_string();
    }
    if let Some((lhs, op, rhs)) = split_top_level_comparison(c) {
        let inverse = match op.as_str() {
            "<" => ">=",
            "<=" => ">",
            ">" => "<=",
            ">=" => "<",
            "==" => "!=",
            "!=" => "==",
            _ => "",
        };
        if !inverse.is_empty() {
            return format!("({lhs}) {inverse} ({rhs})");
        }
    }
    format!("!({c})")
}

fn collect_assignment_facts(source: &str) -> Vec<AssignmentFact> {
    let source = strip_comments(source);
    let body = function_body(&source).unwrap_or(source.as_str());
    let mut out = Vec::new();
    for statement in split_statements(body) {
        let s = statement.trim();
        if s.is_empty() || s.starts_with("return ") || s.starts_with("require(") || s.starts_with("if ") {
            continue;
        }
        if let Some((lhs, rhs)) = split_assignment(s) {
            out.push(AssignmentFact { lhs, rhs });
        }
    }
    out
}

fn split_assignment(statement: &str) -> Option<(String, String)> {
    let bytes = statement.as_bytes();
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] as char {
            '(' => paren += 1,
            ')' => paren -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            '=' if paren >= 0 && bracket >= 0 && brace >= 0 => {
                let prev = if i > 0 { Some(bytes[i - 1] as char) } else { None };
                let next = bytes.get(i + 1).map(|b| *b as char);
                if matches!(prev, Some('=') | Some('!') | Some('<') | Some('>'))
                    || next == Some('=')
                {
                    i += 1;
                    continue;
                }
                let lhs = statement[..i].trim().to_string();
                let rhs = statement[i + 1..].trim().trim_end_matches(';').trim().to_string();
                if !lhs.is_empty() && !rhs.is_empty() {
                    return Some((lhs, rhs));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn simple_identifier(lhs: &str) -> Option<String> {
    let ids = identifiers_in_order(lhs);
    let last = ids.last()?.clone();
    if lhs.contains('[') || lhs.contains('.') {
        return None;
    }
    Some(last)
}

fn expand_expression(expr: &str, assignments: &HashMap<String, String>, depth: usize) -> String {
    if depth == 0 {
        return expr.to_string();
    }
    let mut current = expr.to_string();
    for _ in 0..depth {
        let ids = identifiers_in_order(&current);
        let mut substitutions = HashMap::new();
        for id in ids {
            if let Some(rhs) = assignments.get(&id) {
                if rhs != &id {
                    substitutions.insert(id, format!("({rhs})"));
                }
            }
        }
        if substitutions.is_empty() {
            break;
        }
        let next = substitute_identifiers(&current, &substitutions);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn substitute_identifiers(source: &str, substitutions: &HashMap<String, String>) -> String {
    if substitutions.is_empty() {
        return source.to_string();
    }
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if is_ident_start(c) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i] as char) {
                i += 1;
            }
            let word = &source[start..i];
            if let Some(replacement) = substitutions.get(word) {
                out.push_str(replacement);
            } else {
                out.push_str(word);
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn parse_function_signature(source: &str) -> FunctionSignature {
    let cleaned = strip_comments(source);
    let Some(function_pos) = find_word_from(&cleaned, "function", 0) else {
        return FunctionSignature::default();
    };
    let after = &cleaned[function_pos + "function".len()..];
    let Some(open_rel) = after.find('(') else {
        return FunctionSignature::default();
    };
    let name = after[..open_rel].trim().to_string();
    let open = function_pos + "function".len() + open_rel;
    let Some(close) = matching_delimiter(&cleaned, open, '(', ')') else {
        return FunctionSignature::default();
    };
    let params_text = &cleaned[open + 1..close];
    let params = split_top_level(params_text, ',')
        .into_iter()
        .filter_map(|part| parse_parameter(&part))
        .collect::<Vec<_>>();

    let tail_end = cleaned[close + 1..]
        .find('{')
        .map(|x| close + 1 + x)
        .or_else(|| cleaned[close + 1..].find(';').map(|x| close + 1 + x))
        .unwrap_or(cleaned.len());
    let tail = cleaned[close + 1..tail_end].to_ascii_lowercase();

    FunctionSignature {
        name,
        params,
        is_public: contains_word(&tail, "public"),
        is_external: contains_word(&tail, "external"),
        is_view: contains_word(&tail, "view"),
        is_pure: contains_word(&tail, "pure"),
        has_body: cleaned[close + 1..].contains('{'),
    }
}

fn parse_parameter(text: &str) -> Option<Parameter> {
    let words = identifiers_in_order(text);
    if words.is_empty() {
        return None;
    }
    let name = words.last()?.clone();
    let name_pos = text.rfind(&name)?;
    let ty = text[..name_pos].trim().to_string();
    if ty.is_empty() {
        return None;
    }
    Some(Parameter { ty, name })
}

fn parse_call_args_at(source: &str, local_pos: usize) -> Option<Vec<String>> {
    if local_pos >= source.len() {
        return None;
    }
    let open_rel = source[local_pos..].find('(')?;
    let open = local_pos + open_rel;
    let close = matching_delimiter(source, open, '(', ')')?;
    Some(split_top_level(&source[open + 1..close], ','))
}

fn find_calls_named(source: &str, name: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(found) = find_word_from(source, name, pos) {
        let mut cursor = found + name.len();
        while cursor < source.len() && source.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if source.as_bytes().get(cursor).copied() != Some(b'(') {
            pos = found + name.len();
            continue;
        }
        if let Some(close) = matching_delimiter(source, cursor, '(', ')') {
            out.push(split_top_level(&source[cursor + 1..close], ','));
            pos = close + 1;
        } else {
            break;
        }
    }
    out
}

fn matching_delimiter(source: &str, open: usize, left: char, right: char) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open).copied()? as char != left {
        return None;
    }
    let mut depth = 0i32;
    let mut i = open;
    let mut string: Option<char> = None;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(q) = string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == q {
                string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            string = Some(c);
            i += 1;
            continue;
        }
        if c == left {
            depth += 1;
        } else if c == right {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn split_top_level(source: &str, delimiter: char) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut string: Option<char> = None;
    let mut escape = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(q) = string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == q {
                string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            string = Some(c);
            i += 1;
            continue;
        }
        match c {
            '(' => paren += 1,
            ')' => paren -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            _ if c == delimiter && paren == 0 && bracket == 0 && brace == 0 => {
                out.push(source[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= source.len() {
        let tail = source[start..].trim();
        if !tail.is_empty() {
            out.push(tail.to_string());
        }
    }
    out
}

fn split_statements(source: &str) -> Vec<String> {
    split_top_level(source, ';')
}

fn split_top_level_comparison(source: &str) -> Option<(String, String, String)> {
    let s = strip_outer_parens(source.trim());
    let bytes = s.as_bytes();
    let mut paren = 0i32;
    let mut bracket = 0i32;
    let mut brace = 0i32;
    let mut string: Option<char> = None;
    let mut escape = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(q) = string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == q {
                string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            string = Some(c);
            i += 1;
            continue;
        }
        match c {
            '(' => paren += 1,
            ')' => paren -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            '{' => brace += 1,
            '}' => brace -= 1,
            _ => {}
        }
        if paren == 0 && bracket == 0 && brace == 0 {
            for op in ["<=", ">=", "==", "!=", "<", ">"] {
                if s[i..].starts_with(op) {
                    return Some((
                        s[..i].trim().to_string(),
                        op.to_string(),
                        s[i + op.len()..].trim().to_string(),
                    ));
                }
            }
        }
        i += 1;
    }
    None
}

fn strip_outer_parens(mut source: &str) -> &str {
    loop {
        let s = source.trim();
        if !s.starts_with('(') || !s.ends_with(')') {
            return s;
        }
        let Some(close) = matching_delimiter(s, 0, '(', ')') else {
            return s;
        };
        if close != s.len() - 1 {
            return s;
        }
        source = &s[1..s.len() - 1];
    }
}

fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;
    let mut string: Option<char> = None;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if let Some(q) = string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == q {
                string = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            string = Some(c);
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && bytes.get(i + 1).copied() == Some(b'/') {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            out.push('\n');
            continue;
        }
        if c == '/' && bytes.get(i + 1).copied() == Some(b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn function_body(source: &str) -> Option<&str> {
    let open = source.find('{')?;
    let close = matching_delimiter(source, open, '{', '}')?;
    Some(&source[open + 1..close])
}

fn identifiers_in_text(source: &str) -> BTreeSet<String> {
    identifiers_in_order(source).into_iter().collect()
}

fn identifiers_in_order(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if is_ident_start(c) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i] as char) {
                i += 1;
            }
            out.push(source[start..i].to_string());
        } else {
            i += 1;
        }
    }
    out
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

fn compact_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn canonical_expr(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

fn contains_block_timestamp(source: &str) -> bool {
    canonical_expr(source)
        .to_ascii_lowercase()
        .contains("block.timestamp")
}

fn contains_block_number(source: &str) -> bool {
    canonical_expr(source)
        .to_ascii_lowercase()
        .contains("block.number")
}

fn contains_word(source: &str, word: &str) -> bool {
    find_word_from(source, word, 0).is_some()
}

fn find_word_from(source: &str, word: &str, start: usize) -> Option<usize> {
    if word.is_empty() || start >= source.len() {
        return None;
    }
    let mut cursor = start;
    while let Some(rel) = source[cursor..].find(word) {
        let pos = cursor + rel;
        let before_ok = pos == 0
            || !is_ident_continue(source.as_bytes()[pos - 1] as char);
        let after = pos + word.len();
        let after_ok = after >= source.len()
            || !is_ident_continue(source.as_bytes()[after] as char);
        if before_ok && after_ok {
            return Some(pos);
        }
        cursor = pos + word.len();
        if cursor >= source.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(source: &str) -> FunctionModel {
        let sig = parse_function_signature(source);
        let assignment_facts = collect_assignment_facts(source);
        let assignments = assignment_facts
            .iter()
            .filter_map(|fact| simple_identifier(&fact.lhs).map(|name| (name, fact.rhs.clone())))
            .collect();
        FunctionModel {
            id: 1,
            scope: 10,
            source: source.to_string(),
            sig,
            calls: Vec::new(),
            assignments,
            assignment_facts,
        }
    }

    fn analyze_single(source: &str) -> Option<FindingReason> {
        let m = model(source);
        let mut models = BTreeMap::new();
        models.insert(1, m.clone());
        let auth = direct_auth_summary(&m);
        analyze_freshness(&m, &models, &auth)
    }

    #[test]
    fn catches_unsigned_deadline() {
        let source = r#"
            function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(owner, spender, value));
                require(ECDSA.recover(digest, signature) == owner, "sig");
                require(block.timestamp <= deadline, "expired");
                allowance[owner][spender] = value;
            }
        "#;
        assert_eq!(analyze_single(source), Some(FindingReason::FreshnessNotAuthenticated));
    }

    #[test]
    fn accepts_signed_and_enforced_deadline() {
        let source = r#"
            function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(owner, spender, value, deadline));
                require(ECDSA.recover(digest, signature) == owner, "sig");
                require(block.timestamp <= deadline, "expired");
                allowance[owner][spender] = value;
            }
        "#;
        assert_eq!(analyze_single(source), None);
    }

    #[test]
    fn catches_signed_deadline_not_enforced() {
        let source = r#"
            function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(owner, spender, value, deadline));
                require(ECDSA.recover(digest, signature) == owner, "sig");
                allowance[owner][spender] = value;
            }
        "#;
        assert_eq!(
            analyze_single(source),
            Some(FindingReason::AuthenticatedFreshnessNotEnforced)
        );
    }

    #[test]
    fn catches_signed_block_expiry_wrong_direction() {
        let source = r#"
            function execute(address from, address to, uint256 value, uint256 validThroughBlock, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(from, to, value, validThroughBlock));
                require(ECDSA.recover(digest, signature) == from, "sig");
                require(block.number >= validThroughBlock, "not reached");
                balances[from] -= value;
                balances[to] += value;
            }
        "#;
        assert_eq!(
            analyze_single(source),
            Some(FindingReason::AuthenticatedFreshnessNotEnforced)
        );
    }

    #[test]
    fn catches_signed_round_shape_check_without_monotonicity() {
        let source = r#"
            function execute(address signer, uint64 round, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(signer, round));
                require(ECDSA.recover(digest, signature) == signer, "sig");
                require(round != 0, "round");
                accepted[signer] += 1;
            }
        "#;
        assert_eq!(
            analyze_single(source),
            Some(FindingReason::AuthenticatedFreshnessNotEnforced)
        );
    }

    #[test]
    fn accepts_signed_monotonic_round() {
        let source = r#"
            function execute(address signer, uint64 round, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(signer, round));
                require(ECDSA.recover(digest, signature) == signer, "sig");
                require(uint256(round) > latestRound[signer], "old");
                latestRound[signer] = uint256(round);
            }
        "#;
        assert_eq!(analyze_single(source), None);
    }

    #[test]
    fn catches_stale_signed_oracle_report_without_age_check() {
        let source = r#"
            function updatePrice(address oracle, bytes32 asset, uint256 price, uint256 reportTimestamp, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(oracle, asset, price, reportTimestamp));
                require(ECDSA.recover(digest, signature) == oracle, "sig");
                currentPrice[asset] = price;
            }
        "#;
        assert_eq!(
            analyze_single(source),
            Some(FindingReason::AuthenticatedFreshnessNotEnforced)
        );
    }

    #[test]
    fn accepts_bounded_signed_report_age() {
        let source = r#"
            function updatePrice(address oracle, bytes32 asset, uint256 price, uint256 reportTimestamp, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(oracle, asset, price, reportTimestamp));
                require(ECDSA.recover(digest, signature) == oracle, "sig");
                require(reportTimestamp <= block.timestamp, "future");
                require(block.timestamp - reportTimestamp <= MAX_AGE, "stale");
                currentPrice[asset] = price;
            }
        "#;
        assert_eq!(analyze_single(source), None);
    }

    #[test]
    fn catches_millisecond_timestamp_used_as_seconds() {
        let source = r#"
            function execute(address signer, uint256 issuedAtMs, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(signer, issuedAtMs));
                require(ECDSA.recover(digest, signature) == signer, "sig");
                require(block.timestamp <= issuedAtMs + 300, "stale");
                executed[signer] += 1;
            }
        "#;
        assert_eq!(
            analyze_single(source),
            Some(FindingReason::AuthenticatedFreshnessNotEnforced)
        );
    }

    #[test]
    fn does_not_flag_indefinite_authorization_with_signed_revocation_generation() {
        let source = r#"
            function permit(address owner, address spender, uint256 value, bytes calldata signature) external {
                uint256 authVersion = authorizationVersion[owner];
                bytes32 digest = keccak256(abi.encode(owner, spender, value, authVersion));
                require(ECDSA.recover(digest, signature) == owner, "sig");
                allowance[owner][spender] = value;
            }
        "#;
        assert_eq!(analyze_single(source), None);
    }

    #[test]
    fn absence_rule_is_contextual_not_global() {
        let source = r#"
            function execute(address signer, bytes32 action, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(signer, action));
                require(ECDSA.recover(digest, signature) == signer, "sig");
                used[action] = true;
            }
        "#;
        assert_eq!(analyze_single(source), None);
    }

    #[test]
    fn catches_permit_like_missing_freshness_with_high_context_confidence() {
        let source = r#"
            function execute(address owner, address spender, uint256 value, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encode(owner, spender, value));
                require(ECDSA.recover(digest, signature) == owner, "sig");
                allowance[owner][spender] = value;
            }
        "#;
        assert_eq!(
            analyze_single(source),
            Some(FindingReason::MissingMeaningfulFreshness)
        );
    }

    #[test]
    fn require_parser_uses_first_argument_only() {
        let predicates = collect_required_predicates(
            r#"function f(uint256 deadline) external { require(block.timestamp <= deadline, "expired"); }"#,
        );
        assert!(predicates.iter().any(|p| p.contains("block.timestamp <= deadline")));
        assert!(predicates.iter().all(|p| !p.contains("expired")));
    }

    #[test]
    fn rejects_branch_is_inverted_into_required_predicate() {
        let predicates = collect_required_predicates(
            r#"function f(uint256 validBefore) external { if (!(block.timestamp <= validBefore)) return false; }"#,
        );
        assert!(predicates
            .iter()
            .any(|p| canonical_expr(p).contains("block.timestamp<=validBefore")));
    }
}
