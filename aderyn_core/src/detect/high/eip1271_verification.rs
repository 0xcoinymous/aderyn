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

/// Detects unsafe ERC-1271 (`isValidSignature`) implementations and consumers.
///
/// Aderyn v0.6.8 exposes a rich Solidity AST but no detector-facing SSA/CFG abstraction.  This
/// detector therefore follows the same architecture used by the signature-replay hook: AST nodes
/// establish function boundaries, member accesses, and internal call edges, while a bounded,
/// Solidity-aware source pass models call results, magic-value checks, input dependencies, signer
/// provenance, and state-changing validation helpers.
///
/// The detector intentionally does not key on benchmark IDs, filenames, contract names, addresses,
/// or application-specific constants.  The only protocol constant recognized directly is the
/// ERC-1271 magic value `0x1626ba7e` (plus the equivalent selector expression).
#[derive(Default)]
pub struct EIP1271VerificationDetector {
    found_instances: BTreeMap<(String, usize, String), NodeID>,
}

const MAX_CALL_DEPTH: usize = 5;
const ERC1271_MAGIC: &str = "0x1626ba7e";

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
    returns: Vec<String>,
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
struct FunctionModel {
    id: NodeID,
    scope: NodeID,
    source: String,
    sig: FunctionSignature,
    calls: Vec<CallSite>,
    assignments: HashMap<String, String>,
    member_names: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct InputUse {
    hash: bool,
    signature: bool,
}

impl InputUse {
    fn merge(&mut self, other: InputUse) {
        self.hash |= other.hash;
        self.signature |= other.signature;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LowLevelCallKind {
    StaticCall,
    Call,
    DelegateCall,
}

#[derive(Debug, Clone)]
struct LowLevel1271Call {
    kind: LowLevelCallKind,
    target: String,
    success_var: Option<String>,
    returndata_var: Option<String>,
    hash_expr: Option<String>,
    signature_expr: Option<String>,
    pos: usize,
}

impl IssueDetector for EIP1271VerificationDetector {
    fn detect(&mut self, context: &WorkspaceContext) -> Result<bool, Box<dyn Error>> {
        let models = build_models(context);
        if models.is_empty() {
            return Ok(false);
        }

        let mut vulnerable: BTreeSet<NodeID> = BTreeSet::new();

        // Implementation-side analysis.  We always report on the externally visible
        // isValidSignature function, even when the bad operation lives in an internal helper.
        for model in models.values() {
            if !is_erc1271_implementation(model) {
                continue;
            }

            let bad_shape = !is_canonical_erc1271_shape(&model.sig);
            let bad_state = implementation_changes_state(model.id, &models, MAX_CALL_DEPTH);
            let bad_inputs = if bad_shape {
                false
            } else {
                implementation_ignores_required_inputs(model.id, &models, MAX_CALL_DEPTH)
            };
            let bad_magic = if bad_shape || bad_inputs {
                false
            } else {
                implementation_magic_semantics_bad(model.id, &models, MAX_CALL_DEPTH)
            };
            let bad_identity = implementation_uses_attacker_controlled_identity(
                model.id,
                &models,
                MAX_CALL_DEPTH,
            );
            let bad_self_authorization =
                implementation_has_self_authorizing_registry(model, &models, MAX_CALL_DEPTH);
            let bad_fallback = implementation_has_permissive_zero_owner_fallback(
                model.id,
                &models,
                MAX_CALL_DEPTH,
            );
            let raw_cross_account = implementation_has_explicit_raw_hash_passthrough(
                model.id,
                &models,
                MAX_CALL_DEPTH,
            );

            if bad_shape
                || bad_state
                || bad_inputs
                || bad_magic
                || bad_identity
                || bad_self_authorization
                || bad_fallback
                || raw_cross_account
            {
                vulnerable.insert(model.id);
            }
        }

        // Caller-side validation: low-level call-result handling, exact magic value, returndata
        // shape, direct-interface input forwarding, and EOA/contract branch semantics.
        for model in models.values() {
            if is_erc1271_implementation(model) {
                continue;
            }

            if caller_low_level_validation_bad(model)
                || caller_direct_input_forwarding_bad(model)
                || caller_direct_magic_validation_bad(model)
                || caller_eoa_contract_branch_bad(model)
            {
                vulnerable.insert(model.id);
            }
        }

        // Signer provenance is contextual: an internal verifier accepting an address parameter is
        // not inherently vulnerable.  Walk outward to public/external state-changing entry points
        // and ask where their ERC-1271 signer target comes from.
        for model in models.values() {
            if !model.sig.is_entry_point() || model.sig.is_read_only() {
                continue;
            }
            if !function_has_sensitive_effect(model) {
                continue;
            }
            if entry_has_unsafe_signer_provenance(model.id, &models, MAX_CALL_DEPTH) {
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
        String::from("ERC-1271 Signature Verification Vulnerability")
    }

    fn description(&self) -> String {
        String::from(concat!(
            "ERC-1271 validation is implemented or consumed unsafely. A valid contract signature ",
            "requires successful execution of isValidSignature(bytes32,bytes), the exact ERC-1271 ",
            "magic value 0x1626ba7e, meaningful dependence on both the supplied hash and signature, ",
            "and an independently authorized signer identity. Implementations must not mutate state. ",
            "When using low-level calls, require call success before interpreting return data and ",
            "reject malformed/short responses. Avoid permissive EOA/contract fallbacks and ",
            "attacker-controlled validation contracts; prefer well-reviewed SignatureChecker-style ",
            "helpers where appropriate."
        ))
    }

    fn instances(&self) -> BTreeMap<(String, usize, String), NodeID> {
        self.found_instances.clone()
    }

    fn name(&self) -> String {
        format!("{}", IssueDetectorNamePool::EIP1271Verification)
    }
}

fn build_models(context: &WorkspaceContext) -> BTreeMap<NodeID, FunctionModel> {
    let function_spans: Vec<(NodeID, SrcSpan)> = context
        .function_definitions()
        .into_iter()
        .filter_map(|f| SrcSpan::parse(&f.src).map(|span| (f.id, span)))
        .collect();
    let function_ids: HashSet<NodeID> = function_spans.iter().map(|(id, _)| *id).collect();

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
        call_sites_by_function
            .entry(caller)
            .or_default()
            .push(CallSite { callee, args });
    }

    let mut members_by_function: HashMap<NodeID, BTreeSet<String>> = HashMap::new();
    for member in context.member_accesss() {
        let Some(node_span) = SrcSpan::parse(&member.src) else {
            continue;
        };
        let Some((id, _)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        members_by_function
            .entry(id)
            .or_default()
            .insert(member.member_name.clone());
    }

    let mut models = BTreeMap::new();
    for function in context.function_definitions() {
        let source = function.peek(context).unwrap_or_default();
        let sig = parse_function_signature(&source);
        let assignments = collect_assignments(&source);
        models.insert(
            function.id,
            FunctionModel {
                id: function.id,
                scope: function.scope,
                source,
                sig,
                calls: call_sites_by_function.remove(&function.id).unwrap_or_default(),
                assignments,
                member_names: members_by_function.remove(&function.id).unwrap_or_default(),
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

fn is_erc1271_implementation(model: &FunctionModel) -> bool {
    model.sig.has_body && model.sig.name == "isValidSignature"
}

fn is_canonical_erc1271_shape(sig: &FunctionSignature) -> bool {
    sig.params.len() == 2
        && normalize_type(&sig.params[0].ty) == "bytes32"
        && normalize_type(&sig.params[1].ty) == "bytes"
        && sig.returns.len() == 1
        && normalize_type(&sig.returns[0]) == "bytes4"
}

fn implementation_changes_state(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let mut visited = BTreeSet::new();
    recursive_state_effect(root, models, depth, &mut visited)
}

fn recursive_state_effect(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
    visited: &mut BTreeSet<NodeID>,
) -> bool {
    if depth == 0 || !visited.insert(id) {
        return false;
    }
    let Some(model) = models.get(&id) else {
        return false;
    };
    if direct_state_effect(model) {
        return true;
    }
    model
        .calls
        .iter()
        .any(|call| recursive_state_effect(call.callee, models, depth - 1, visited))
}

fn direct_state_effect(model: &FunctionModel) -> bool {
    if model.sig.is_read_only() {
        return false;
    }

    let body = function_body(&model.source).unwrap_or(&model.source);
    let compacted = compact(body);
    if contains_word(body, "emit")
        || compacted.contains(".call(")
        || compacted.contains(".delegatecall(")
        || compacted.contains(".send(")
        || compacted.contains(".transfer(")
        || contains_word(body, "selfdestruct")
        || contains_word(body, "delete")
        || compacted.contains("sstore(")
    {
        return true;
    }

    let locals = collect_probable_local_names(model);
    for statement in split_statements(body) {
        let s = statement.trim();
        if s.is_empty() {
            continue;
        }
        if let Some(base) = mutation_lvalue_base(s) {
            if !locals.contains(&base) && !is_builtin_identifier(&base) {
                return true;
            }
        }
    }
    false
}

fn function_has_sensitive_effect(model: &FunctionModel) -> bool {
    if model.sig.is_read_only() {
        return false;
    }
    direct_state_effect(model)
}

fn implementation_ignores_required_inputs(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let Some(model) = models.get(&root) else {
        return false;
    };
    if model.sig.params.len() < 2 {
        return false;
    }
    let hash = model.sig.params[0].name.clone();
    let signature = model.sig.params[1].name.clone();
    if hash.is_empty() || signature.is_empty() {
        return true;
    }

    let mut hash_aliases = BTreeSet::new();
    hash_aliases.insert(hash);
    let mut signature_aliases = BTreeSet::new();
    signature_aliases.insert(signature);
    let mut visited = BTreeSet::new();
    let use_ = collect_strong_input_use(
        root,
        models,
        &hash_aliases,
        &signature_aliases,
        depth,
        &mut visited,
    );
    !(use_.hash && use_.signature)
}

fn collect_strong_input_use(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    hash_aliases: &BTreeSet<String>,
    signature_aliases: &BTreeSet<String>,
    depth: usize,
    visited: &mut BTreeSet<NodeID>,
) -> InputUse {
    if depth == 0 || !visited.insert(id) {
        return InputUse::default();
    }
    let Some(model) = models.get(&id) else {
        return InputUse::default();
    };

    let mut result = InputUse::default();
    for call in scan_call_expressions(&model.source) {
        if !is_strong_verification_call(&call.name) {
            continue;
        }
        if call.args.iter().any(|arg| {
            expr_depends_on_aliases(arg, hash_aliases, &model.assignments, 7)
        }) {
            result.hash = true;
        }
        if call.args.iter().any(|arg| {
            expr_depends_on_aliases(arg, signature_aliases, &model.assignments, 7)
        }) {
            result.signature = true;
        }
    }

    for call in &model.calls {
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        let mut callee_hash_aliases = BTreeSet::new();
        let mut callee_signature_aliases = BTreeSet::new();
        for (i, param) in callee.sig.params.iter().enumerate() {
            let Some(arg) = call.args.get(i) else {
                continue;
            };
            if expr_depends_on_aliases(arg, hash_aliases, &model.assignments, 7) {
                callee_hash_aliases.insert(param.name.clone());
            }
            if expr_depends_on_aliases(arg, signature_aliases, &model.assignments, 7) {
                callee_signature_aliases.insert(param.name.clone());
            }
        }
        let mut branch_visited = visited.clone();
        result.merge(collect_strong_input_use(
            call.callee,
            models,
            &callee_hash_aliases,
            &callee_signature_aliases,
            depth - 1,
            &mut branch_visited,
        ));
    }

    result
}

fn is_strong_verification_call(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "ecrecover"
        || n == "recover"
        || n == "tryrecover"
        || n == "verify"
        || n == "verifysignature"
        || n == "isvalidsignature"
        || n == "isvalidsignaturenow"
        || n == "isvalidsignaturenowcalldata"
        || n == "isvaliderc1271signaturenow"
        || n == "isvaliderc1271signaturenowcalldata"
}

fn implementation_magic_semantics_bad(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let reachable = reachable_functions(root, models, depth);
    for id in reachable {
        let Some(model) = models.get(&id) else {
            continue;
        };
        if !source_has_strong_verification_call(&model.source) {
            continue;
        }
        if local_magic_semantics_bad(model) {
            return true;
        }
    }
    // If strong input use came only from an unresolved pattern, stay conservative instead of
    // inventing a magic-value failure.
    false
}

fn local_magic_semantics_bad(model: &FunctionModel) -> bool {
    let returns = collect_return_expressions(&model.source);
    if returns.is_empty() {
        return true;
    }
    if !returns.iter().any(|expr| is_magic_expr(expr)) {
        return true;
    }

    let verifier_vars = collect_verifier_result_variables(model);

    for expr in &returns {
        let Some((condition, yes, no)) = split_ternary(expr) else {
            continue;
        };
        if !condition_depends_on_verifier(condition, &verifier_vars) {
            continue;
        }
        let success_true = condition_true_means_success(condition);
        let yes_magic = is_magic_expr(yes);
        let no_magic = is_magic_expr(no);
        if success_true && !yes_magic && no_magic {
            return true;
        }
        if !success_true && yes_magic && !no_magic {
            return true;
        }
    }

    for (condition, returned) in collect_if_return_pairs(&model.source) {
        if !condition_depends_on_verifier(&condition, &verifier_vars) {
            continue;
        }
        let success_true = condition_true_means_success(&condition);
        if success_true && !is_magic_expr(&returned) && returns.iter().any(|r| is_magic_expr(r)) {
            return true;
        }
        if !success_true && is_magic_expr(&returned) {
            return true;
        }
    }

    false
}

fn source_has_strong_verification_call(source: &str) -> bool {
    scan_call_expressions(source)
        .iter()
        .any(|call| is_strong_verification_call(&call.name))
}

fn collect_verifier_result_variables(model: &FunctionModel) -> BTreeSet<String> {
    model
        .assignments
        .iter()
        .filter_map(|(lhs, rhs)| {
            source_has_strong_verification_call(rhs).then_some(lhs.clone())
        })
        .collect()
}

fn condition_depends_on_verifier(condition: &str, vars: &BTreeSet<String>) -> bool {
    source_has_strong_verification_call(condition)
        || vars.iter().any(|var| contains_word(condition, var))
        || contains_word(condition, "recovered")
        || contains_word(condition, "valid")
        || contains_word(condition, "ok")
}

fn condition_true_means_success(condition: &str) -> bool {
    let c = compact(condition);
    if c.starts_with('!') {
        return false;
    }
    if c.contains("!=") {
        return false;
    }
    true
}

fn implementation_uses_attacker_controlled_identity(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let Some(root_model) = models.get(&root) else {
        return false;
    };
    let signature_param = root_model
        .sig
        .params
        .get(1)
        .map(|p| p.name.clone())
        .unwrap_or_default();
    for id in reachable_functions(root, models, depth) {
        let Some(model) = models.get(&id) else {
            continue;
        };
        let source = &model.source;
        let has_dynamic_target_call = source.contains(".staticcall(") || source.contains(".call(");
        let signature_address_decode = (!signature_param.is_empty()
            && (source.contains(&format!("{}.offset", signature_param))
                || source.contains(&format!("keccak256({})", signature_param))))
            || source.contains("calldataload(signature.offset)");
        if has_dynamic_target_call && signature_address_decode && !source.contains("isValidSignature.selector") {
            return true;
        }
    }
    false
}

fn implementation_has_self_authorizing_registry(
    root: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let mut registry_bases = BTreeSet::new();
    for id in reachable_functions(root.id, models, depth) {
        let Some(model) = models.get(&id) else {
            continue;
        };
        let verifier_vars = collect_verifier_result_variables(model);
        for var in verifier_vars {
            for base in mapping_bases_indexed_by(&model.source, &var) {
                registry_bases.insert(base);
            }
        }
    }
    if registry_bases.is_empty() {
        return false;
    }

    for sibling in models.values().filter(|m| m.scope == root.scope) {
        if !sibling.sig.is_entry_point() || sibling.sig.is_read_only() {
            continue;
        }
        if has_access_control_signal(&sibling.source) {
            continue;
        }
        for base in &registry_bases {
            let compacted = compact(&sibling.source);
            let needle = format!("{}[msg.sender]=true", base);
            if compacted.contains(&needle) {
                return true;
            }
        }
    }
    false
}

fn implementation_has_permissive_zero_owner_fallback(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    for id in reachable_functions(root, models, depth) {
        let Some(model) = models.get(&id) else {
            continue;
        };
        let compacted = compact(&model.source);
        if !compacted.contains("address(0)") || !source_has_strong_verification_call(&model.source) {
            continue;
        }
        // High-confidence form: a zero policy/owner branch accepts any nonzero recovered address.
        if compacted.contains("==address(0))return")
            && compacted.contains("!=address(0)?")
            && source_has_magic(&model.source)
        {
            return true;
        }
    }
    false
}

fn implementation_has_explicit_raw_hash_passthrough(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let reachable = reachable_functions(root, models, depth);
    let mut has_passthrough = false;
    let mut has_recovery = false;
    let mut has_domain_binding = false;

    for id in &reachable {
        let Some(model) = models.get(id) else {
            continue;
        };
        if model.source.contains("address(this)") || model.source.contains("block.chainid") {
            has_domain_binding = true;
        }
        if scan_call_expressions(&model.source)
            .iter()
            .any(|call| matches!(call.name.as_str(), "recover" | "tryRecover" | "ecrecover"))
        {
            has_recovery = true;
        }
        if is_identity_bytes32_helper(model) {
            has_passthrough = true;
        }
    }

    // Do not flag ordinary ERC-1271 implementations that simply verify the supplied hash.  The
    // standard itself does not require account rehashing.  This rule only recognizes an explicit,
    // account-independent passthrough helper, which is a strong local signal of the 2023
    // cross-smart-account failure mode and avoids blanket `address(this)`/chainid requirements.
    has_passthrough && has_recovery && !has_domain_binding
}

fn is_identity_bytes32_helper(model: &FunctionModel) -> bool {
    if !model.sig.is_pure || model.sig.params.len() != 1 || model.sig.returns.len() != 1 {
        return false;
    }
    if normalize_type(&model.sig.params[0].ty) != "bytes32"
        || normalize_type(&model.sig.returns[0]) != "bytes32"
    {
        return false;
    }
    let param = &model.sig.params[0].name;
    let returns = collect_return_expressions(&model.source);
    returns.len() == 1 && compact(&returns[0]) == compact(param)
}

fn caller_low_level_validation_bad(model: &FunctionModel) -> bool {
    let facts = collect_low_level_1271_calls(model);
    for fact in facts {
        if fact.kind != LowLevelCallKind::StaticCall {
            // ERC-1271 validation must be observational from the caller's perspective.  A raw
            // CALL/DELEGATECALL can permit validation-side state changes and is not a safe
            // substitute for STATICCALL.
            return true;
        }
        let Some(success) = &fact.success_var else {
            // Gnosis Pay / Zodiac class: returndata is interpreted while call success is discarded.
            return true;
        };
        let Some(ret) = &fact.returndata_var else {
            // A successful STATICCALL is not equivalent to a valid ERC-1271 signature.
            return true;
        };
        if let Some((hash_param, signature_param)) = hash_and_signature_parameter_names(&model.sig) {
            if fact.hash_expr.as_deref().is_some_and(|expr| {
                !expr_depends_on_name(expr, &hash_param, &model.assignments, 7)
            }) || fact.signature_expr.as_deref().is_some_and(|expr| {
                !expr_depends_on_name(expr, &signature_param, &model.assignments, 7)
            }) {
                // A correct low-level call is still unsafe if a wrapper replaces the caller's
                // hash/signature with a fixed or unrelated value.
                return true;
            }
        }

        let after = model.source.get(fact.pos..).unwrap_or(&model.source);
        // Count the tuple declaration as one occurrence and require at least one additional use.
        // Looking only after `.staticcall` would falsely flag safe `(bool success, bytes memory ret)`
        // assignments because the declaration is located before the call expression.
        if count_word(&model.source, success) < 2 {
            return true;
        }
        if returndata_empty_path_accepts(after, ret) {
            return true;
        }
        if failed_call_path_accepts_magic(after, success) {
            return true;
        }
        if !returndata_shape_is_safe(after, ret) {
            return true;
        }
        if !has_exact_magic_equality(after) {
            return true;
        }
    }
    false
}

fn caller_direct_input_forwarding_bad(model: &FunctionModel) -> bool {
    let Some((hash_param, signature_param)) = hash_and_signature_parameter_names(&model.sig) else {
        return false;
    };
    for call in collect_direct_is_valid_signature_calls(&model.source) {
        if call.args.len() < 2 {
            continue;
        }
        if !expr_depends_on_name(&call.args[0], &hash_param, &model.assignments, 7)
            || !expr_depends_on_name(&call.args[1], &signature_param, &model.assignments, 7)
        {
            return true;
        }
    }
    false
}


fn caller_direct_magic_validation_bad(model: &FunctionModel) -> bool {
    let calls = collect_direct_is_valid_signature_calls(&model.source);
    if calls.is_empty() {
        return false;
    }

    let compacted = compact(&model.source);
    for call in calls {
        // If the direct call participates in an exact magic-value equality in the same statement,
        // it is safe.  This covers `return wallet.isValidSignature(...) == MAGIC` and requires.
        let call_compact = format!("isValidSignature({})", compact(&call.args.join(",")));
        if let Some(call_pos) = compacted.find(&call_compact) {
            let stmt_start = compacted[..call_pos].rfind(';').map(|p| p + 1).unwrap_or(0);
            let stmt_end = compacted[call_pos..]
                .find(';')
                .map(|p| call_pos + p)
                .unwrap_or(compacted.len());
            let stmt = &compacted[stmt_start..stmt_end];
            if has_exact_magic_equality(stmt) {
                continue;
            }
        }

        // Otherwise inspect an assigned bytes4 result.  Raw bytes4-returning wrappers are allowed
        // to forward the protocol result to an outer caller; boolean/policy wrappers must compare
        // the result against the exact ERC-1271 magic value before accepting it.
        if let Some(result_var) = direct_call_result_variable(&model.source, &call) {
            if has_exact_magic_comparison_for_var(&model.source, &result_var) {
                continue;
            }
            if model.sig.returns.iter().any(|ty| normalize_type(ty) == "bytes4")
                && !function_has_sensitive_effect(model)
            {
                continue;
            }
            return true;
        }
    }
    false
}

fn direct_call_result_variable(source: &str, call: &ParsedCall) -> Option<String> {
    let needle = format!(".isValidSignature({})", call.args.join(","));
    let compact_source = compact(source);
    let compact_needle = compact(&needle);
    let pos = compact_source.find(&compact_needle)?;
    let stmt_start = compact_source[..pos].rfind(';').map(|p| p + 1).unwrap_or(0);
    let prefix = &compact_source[stmt_start..pos];
    let eq = prefix.rfind('=')?;
    if eq > 0 && matches!(prefix.as_bytes().get(eq - 1).copied(), Some(b'=' | b'!' | b'<' | b'>')) {
        return None;
    }
    last_identifier(&prefix[..eq])
}

fn has_exact_magic_comparison_for_var(source: &str, var: &str) -> bool {
    let c = compact(source).to_ascii_lowercase();
    let v = compact(var).to_ascii_lowercase();
    if c.contains(&format!("{}=={}", v, ERC1271_MAGIC))
        || c.contains(&format!("{}=={}", ERC1271_MAGIC, v))
    {
        return true;
    }
    if (c.contains(&format!("{}==", v)) || c.contains(&format!("=={}", v)))
        && (c.contains("isvalidsignature.selector") || contains_magic_identifier(source))
    {
        return true;
    }
    false
}

fn caller_eoa_contract_branch_bad(model: &FunctionModel) -> bool {
    let compacted = compact(&model.source);
    if !compacted.contains(".code.length") {
        return false;
    }

    // Explicitly accepting an EOA without cryptographic recovery.
    if compacted.contains(".code.length==0)returntrue") {
        return true;
    }

    // Reversed branch: contracts are sent through ECDSA recovery while the no-code branch is sent
    // to ERC-1271.  This is deliberately narrow to avoid penalizing legitimate SignatureChecker
    // patterns (and newer EIP-7702-aware variations that do not use this exact split).
    let contract_branch = compacted.contains(".code.length!=0") || compacted.contains(".code.length>0");
    contract_branch
        && (compacted.contains("recover(") || compacted.contains("ecrecover("))
        && compacted.contains(".staticcall(")
        && compacted.contains("isValidSignature.selector")
}

fn entry_has_unsafe_signer_provenance(
    entry: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    let Some(model) = models.get(&entry) else {
        return false;
    };
    let targets = validation_targets_in_namespace(entry, models, depth);
    if targets.is_empty() {
        return false;
    }

    for target in targets {
        let target_ids = identifiers_in_text(&target);
        let param = model
            .sig
            .params
            .iter()
            .find(|p| normalize_type(&p.ty) == "address" && target_ids.contains(&p.name));

        if let Some(param) = param {
            if path_has_signer_authorization_guard(entry, &param.name, models, depth) {
                continue;
            }
            if path_has_correct_eoa_contract_branch(entry, models, depth) {
                // Conservative FP control: a generic SignatureChecker-like API may intentionally
                // accept a caller-selected signer.  We only diagnose arbitrary caller-selected
                // signers when the path is contract-only ERC-1271 and lacks independent policy.
                continue;
            }
            if path_has_contract_only_erc1271(entry, models, depth) {
                return true;
            }
        } else if let Some(state_like) = single_identifier_expr(&target) {
            if scope_has_unguarded_assignment(model.scope, &state_like, models) {
                return true;
            }
        }
    }
    false
}

fn validation_targets_in_namespace(
    id: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> BTreeSet<String> {
    if depth == 0 {
        return BTreeSet::new();
    }
    let Some(model) = models.get(&id) else {
        return BTreeSet::new();
    };
    let mut out: BTreeSet<String> = direct_erc1271_target_exprs(model).into_iter().collect();

    for call in &model.calls {
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        let substitutions: HashMap<String, String> = callee
            .sig
            .params
            .iter()
            .enumerate()
            .filter_map(|(i, p)| call.args.get(i).map(|arg| (p.name.clone(), arg.clone())))
            .collect();
        for target in validation_targets_in_namespace(call.callee, models, depth - 1) {
            out.insert(substitute_identifiers(&target, &substitutions));
        }
    }
    out
}

fn direct_erc1271_target_exprs(model: &FunctionModel) -> Vec<String> {
    let mut out = Vec::new();
    for fact in collect_low_level_1271_calls(model) {
        out.push(fact.target);
    }

    let source = &model.source;
    let mut from = 0;
    while let Some(rel) = source[from..].find(".isValidSignature(") {
        let dot = from + rel;
        if let Some(target) = expression_before_member(source, dot) {
            out.push(unwrap_interface_cast_argument(&target));
        }
        from = dot + ".isValidSignature(".len();
    }
    out
}

fn path_has_signer_authorization_guard(
    root: NodeID,
    signer: &str,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    for id in reachable_functions(root, models, depth) {
        let Some(model) = models.get(&id) else {
            continue;
        };
        let c = compact(&model.source);
        let indexed = format!("[{}]", compact(signer));
        if c.contains(&indexed)
            && (c.contains("require(") || c.contains("if(!") || c.contains("if(") && c.contains("returnfalse"))
        {
            return true;
        }
        if (c.contains(&format!("{}==", compact(signer)))
            || c.contains(&format!("=={}", compact(signer))))
            && !c.contains(&format!("{}==address(0)", compact(signer)))
        {
            return true;
        }
    }
    false
}

fn path_has_correct_eoa_contract_branch(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    reachable_functions(root, models, depth).into_iter().any(|id| {
        models.get(&id).is_some_and(|m| {
            let c = compact(&m.source);
            c.contains(".code.length==0")
                && (c.contains("recover(") || c.contains("ecrecover("))
                && c.contains(".staticcall(")
                && c.contains("isValidSignature.selector")
                && has_exact_magic_equality(&m.source)
                && !caller_eoa_contract_branch_bad(m)
        })
    })
}

fn path_has_contract_only_erc1271(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> bool {
    reachable_functions(root, models, depth).into_iter().any(|id| {
        models.get(&id).is_some_and(|m| {
            (m.source.contains(".isValidSignature(") || !collect_low_level_1271_calls(m).is_empty())
                && !m.source.contains(".code.length")
        })
    })
}

fn scope_has_unguarded_assignment(
    scope: NodeID,
    variable: &str,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    for sibling in models.values().filter(|m| m.scope == scope) {
        if !sibling.sig.is_entry_point() || sibling.sig.is_read_only() {
            continue;
        }
        if has_access_control_signal(&sibling.source) {
            continue;
        }
        for statement in split_statements(&sibling.source) {
            let Some((lhs, _)) = split_assignment(&statement) else {
                continue;
            };
            let Some(base) = last_identifier(lhs) else {
                continue;
            };
            if base == variable {
                return true;
            }
        }
    }
    false
}

fn has_access_control_signal(source: &str) -> bool {
    let c = compact(source);
    if c.contains("msg.sender==") || c.contains("==msg.sender") || c.contains("msg.sender!=") {
        return true;
    }
    let header = source.split('{').next().unwrap_or(source);
    identifier_sequence(header)
        .iter()
        .any(|id| id.to_ascii_lowercase().starts_with("only"))
}

fn collect_low_level_1271_calls(model: &FunctionModel) -> Vec<LowLevel1271Call> {
    let source = &model.source;
    if !source.contains(".staticcall(")
        && !source.contains(".call(")
        && !source.contains(".delegatecall(")
    {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (needle, kind) in [
        (".staticcall(", LowLevelCallKind::StaticCall),
        (".delegatecall(", LowLevelCallKind::DelegateCall),
        (".call(", LowLevelCallKind::Call),
    ] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(needle) {
            let dot = from + rel;
            let Some(open) = source[dot..].find('(').map(|x| dot + x) else {
                break;
            };
            let Some(close) = matching_delimiter(source, open, '(', ')') else {
                break;
            };
            let call_arg = source[open + 1..close].trim();
            if !looks_like_erc1271_payload(call_arg) {
                from = close + 1;
                continue;
            }

            let target = expression_before_member(source, dot).unwrap_or_default();
            let statement_start = source[..dot]
                .rfind(';')
                .or_else(|| source[..dot].rfind('{'))
                .map(|p| p + 1)
                .unwrap_or(0);
            let prefix = source[statement_start..dot].trim();
            let (success_var, returndata_var) = parse_low_level_tuple_lhs(prefix);
            let (hash_expr, signature_expr) = parse_erc1271_payload_arguments(call_arg);
            out.push(LowLevel1271Call {
                kind,
                target,
                success_var,
                returndata_var,
                hash_expr,
                signature_expr,
                pos: dot,
            });
            from = close + 1;
        }
    }
    out.sort_by_key(|fact| fact.pos);
    out
}

fn parse_low_level_tuple_lhs(prefix: &str) -> (Option<String>, Option<String>) {
    let Some(eq) = prefix.rfind('=') else {
        return (None, None);
    };
    let lhs = prefix[..eq].trim();
    let Some(open) = lhs.rfind('(') else {
        return (None, None);
    };
    let Some(close) = matching_delimiter(lhs, open, '(', ')') else {
        return (None, None);
    };
    let parts = split_top_level(&lhs[open + 1..close], ',');
    let first = parts
        .first()
        .and_then(|p| (!p.trim().is_empty()).then(|| last_identifier(p)).flatten());
    let second = parts
        .get(1)
        .and_then(|p| (!p.trim().is_empty()).then(|| last_identifier(p)).flatten());
    (first, second)
}

fn looks_like_erc1271_payload(call_arg: &str) -> bool {
    call_arg.contains("isValidSignature.selector")
        || call_arg.contains("isValidSignature(bytes32,bytes)")
        || call_arg.contains("isValidSignature(bytes32, bytes)")
}

fn parse_erc1271_payload_arguments(call_arg: &str) -> (Option<String>, Option<String>) {
    for encoder in ["encodeWithSelector", "encodeWithSignature"] {
        let Some(pos) = call_arg.find(encoder) else {
            continue;
        };
        let Some(open) = call_arg[pos..].find('(').map(|x| pos + x) else {
            continue;
        };
        let Some(close) = matching_delimiter(call_arg, open, '(', ')') else {
            continue;
        };
        let args = split_top_level(&call_arg[open + 1..close], ',');
        return (args.get(1).cloned(), args.get(2).cloned());
    }
    (None, None)
}

fn returndata_shape_is_safe(source: &str, ret: &str) -> bool {
    let c = compact(source);
    let r = compact(ret);
    c.contains(&format!("{}.length>=32", r))
        || c.contains(&format!("{}.length==32", r))
        || c.contains(&format!("abi.decode({},(bytes4))", r))
        || c.contains(&format!("abi.decode({},(bytes32))", r))
}

fn returndata_empty_path_accepts(source: &str, ret: &str) -> bool {
    let c = compact(source);
    let needle = format!("{}.length==0", compact(ret));
    c.find(&needle)
        .is_some_and(|p| c[p..].chars().take(120).collect::<String>().contains("returntrue"))
}

fn failed_call_path_accepts_magic(source: &str, success: &str) -> bool {
    let c = compact(source);
    let s = compact(success);
    let needle = format!("if({})", s);
    let Some(pos) = c.find(&needle) else {
        return false;
    };
    let tail = &c[pos + needle.len()..];
    // If the success branch returns, yet a later return still accepts the magic value, revert data
    // can be interpreted as a valid response.
    tail.contains("return") && source_has_magic(tail) && tail.matches("return").count() >= 2
}

fn has_exact_magic_equality(source: &str) -> bool {
    let c = compact(source).to_ascii_lowercase();
    c.contains("==0x1626ba7e")
        || c.contains("0x1626ba7e==")
        || (c.contains("==") && c.contains("isvalidsignature.selector"))
        || (c.contains("==") && contains_magic_identifier(source))
}

fn source_has_magic(source: &str) -> bool {
    source.to_ascii_lowercase().contains(ERC1271_MAGIC) || contains_magic_identifier(source)
}

fn contains_magic_identifier(source: &str) -> bool {
    identifier_sequence(source).iter().any(|id| {
        let x = id.to_ascii_lowercase();
        x == "magic"
            || x == "magicvalue"
            || x == "magic_value"
            || x.contains("erc1271_magic")
            || x.contains("eip1271_magic")
    })
}

#[derive(Debug, Clone)]
struct ParsedCall {
    name: String,
    args: Vec<String>,
}

fn scan_call_expressions(source: &str) -> Vec<ParsedCall> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        let mut j = i;
        while j > 0 && source.as_bytes()[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        let end = j;
        while j > 0 && is_ident_continue(source.as_bytes()[j - 1]) {
            j -= 1;
        }
        if j == end || !is_ident_start(source.as_bytes()[j]) {
            i += 1;
            continue;
        }
        let name = source[j..end].to_string();
        let Some(close) = matching_delimiter(source, i, '(', ')') else {
            i += 1;
            continue;
        };
        out.push(ParsedCall {
            name,
            args: split_top_level(&source[i + 1..close], ','),
        });
        i = close + 1;
    }
    out
}

fn collect_direct_is_valid_signature_calls(source: &str) -> Vec<ParsedCall> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = source[from..].find(".isValidSignature(") {
        let dot = from + rel;
        let open = dot + ".isValidSignature".len();
        let Some(close) = matching_delimiter(source, open, '(', ')') else {
            break;
        };
        out.push(ParsedCall {
            name: "isValidSignature".into(),
            args: split_top_level(&source[open + 1..close], ','),
        });
        from = close + 1;
    }
    out
}

fn hash_and_signature_parameter_names(sig: &FunctionSignature) -> Option<(String, String)> {
    let hash = sig
        .params
        .iter()
        .find(|p| normalize_type(&p.ty) == "bytes32" && !p.name.is_empty())?
        .name
        .clone();
    let signature = sig
        .params
        .iter()
        .find(|p| normalize_type(&p.ty) == "bytes" && !p.name.is_empty())?
        .name
        .clone();
    Some((hash, signature))
}

fn reachable_functions(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> BTreeSet<NodeID> {
    fn visit(
        id: NodeID,
        models: &BTreeMap<NodeID, FunctionModel>,
        depth: usize,
        out: &mut BTreeSet<NodeID>,
    ) {
        if depth == 0 || !out.insert(id) {
            return;
        }
        let Some(model) = models.get(&id) else {
            return;
        };
        for call in &model.calls {
            visit(call.callee, models, depth - 1, out);
        }
    }
    let mut out = BTreeSet::new();
    visit(root, models, depth, &mut out);
    out
}

fn mapping_bases_indexed_by(source: &str, index: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let needle = format!("[{}]", compact(index));
    let c = compact(source);
    let mut from = 0;
    while let Some(rel) = c[from..].find(&needle) {
        let pos = from + rel;
        let prefix = &c[..pos];
        if let Some(base) = last_identifier(prefix) {
            out.insert(base);
        }
        from = pos + needle.len();
    }
    out
}

fn collect_return_expressions(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find_word_from(source, "return", from) {
        let rest = &source[pos + "return".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        out.push(rest[..end].trim().to_string());
        from = pos + "return".len() + end + 1;
    }
    out
}

fn collect_if_return_pairs(source: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = find_word_from(source, "if", from) {
        let Some(open) = source[pos + 2..].find('(').map(|x| pos + 2 + x) else {
            break;
        };
        let Some(close) = matching_delimiter(source, open, '(', ')') else {
            break;
        };
        let condition = source[open + 1..close].trim().to_string();
        let after = source[close + 1..].trim_start();
        if after.starts_with("return") {
            let expr = &after["return".len()..];
            let end = expr.find(';').unwrap_or(expr.len());
            out.push((condition, expr[..end].trim().to_string()));
        } else if after.starts_with('{') {
            if let Some(end_brace) = matching_delimiter(after, 0, '{', '}') {
                let block = &after[1..end_brace];
                if let Some(rpos) = find_word_from(block, "return", 0) {
                    let expr = &block[rpos + "return".len()..];
                    let end = expr.find(';').unwrap_or(expr.len());
                    out.push((condition, expr[..end].trim().to_string()));
                }
            }
        }
        from = close + 1;
    }
    out
}

fn split_ternary(expr: &str) -> Option<(&str, &str, &str)> {
    let q = find_top_level_char(expr, '?')?;
    let colon = find_top_level_char(&expr[q + 1..], ':')? + q + 1;
    Some((expr[..q].trim(), expr[q + 1..colon].trim(), expr[colon + 1..].trim()))
}

fn is_magic_expr(expr: &str) -> bool {
    let c = compact(expr).to_ascii_lowercase();
    c.contains(ERC1271_MAGIC)
        || c.contains("isvalidsignature.selector")
        || identifier_sequence(expr).iter().any(|id| {
            let x = id.to_ascii_lowercase();
            x == "magic"
                || x == "magicvalue"
                || x == "magic_value"
                || x.contains("erc1271_magic")
                || x.contains("eip1271_magic")
        })
}

fn expr_depends_on_aliases(
    expr: &str,
    aliases: &BTreeSet<String>,
    assignments: &HashMap<String, String>,
    depth: usize,
) -> bool {
    if aliases.iter().any(|name| contains_word(expr, name)) {
        return true;
    }
    if depth == 0 {
        return false;
    }
    identifiers_in_text(expr).into_iter().any(|id| {
        assignments.get(&id).is_some_and(|rhs| {
            expr_depends_on_aliases(rhs, aliases, assignments, depth - 1)
        })
    })
}

fn expr_depends_on_name(
    expr: &str,
    name: &str,
    assignments: &HashMap<String, String>,
    depth: usize,
) -> bool {
    let mut aliases = BTreeSet::new();
    aliases.insert(name.to_string());
    expr_depends_on_aliases(expr, &aliases, assignments, depth)
}

fn expression_before_member(source: &str, dot: usize) -> Option<String> {
    let prefix = source.get(..dot)?.trim_end();
    if prefix.is_empty() {
        return None;
    }
    if prefix.ends_with(')') {
        let close = prefix.len() - 1;
        let open = matching_delimiter_backward(prefix, close, '(', ')')?;
        let mut start = open;
        while start > 0 && is_ident_continue(prefix.as_bytes()[start - 1]) {
            start -= 1;
        }
        return Some(prefix[start..].trim().to_string());
    }
    let mut start = prefix.len();
    while start > 0
        && (is_ident_continue(prefix.as_bytes()[start - 1])
            || matches!(prefix.as_bytes()[start - 1], b'.' | b']' | b'['))
    {
        start -= 1;
    }
    Some(prefix[start..].trim().to_string())
}

fn unwrap_interface_cast_argument(expr: &str) -> String {
    let e = expr.trim();
    if !e.ends_with(')') {
        return e.to_string();
    }
    let Some(open) = e.find('(') else {
        return e.to_string();
    };
    let Some(close) = matching_delimiter(e, open, '(', ')') else {
        return e.to_string();
    };
    if close + 1 == e.len() {
        return e[open + 1..close].trim().to_string();
    }
    e.to_string()
}

fn single_identifier_expr(expr: &str) -> Option<String> {
    let ids = identifier_sequence(expr)
        .into_iter()
        .filter(|id| !is_language_keyword(id))
        .collect::<Vec<_>>();
    (ids.len() == 1).then(|| ids[0].clone())
}

fn collect_probable_local_names(model: &FunctionModel) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = model
        .sig
        .params
        .iter()
        .filter(|p| !p.name.is_empty())
        .map(|p| p.name.clone())
        .collect();
    for statement in split_statements(&model.source) {
        if !looks_like_variable_declaration(&statement) {
            continue;
        }
        if let Some((lhs, _)) = split_assignment(&statement) {
            if let Some(name) = last_identifier(lhs) {
                out.insert(name);
            }
        }
    }
    out
}

fn looks_like_variable_declaration(statement: &str) -> bool {
    let s = statement.trim();
    if s.starts_with('(') {
        return s.contains("bool ")
            || s.contains("bytes ")
            || s.contains("bytes32 ")
            || s.contains("address ")
            || s.contains("uint")
            || s.contains("int");
    }
    let Some(first) = identifier_sequence(s).first().cloned() else {
        return false;
    };
    is_type_or_location_keyword(&first) || first.starts_with('I') && s.contains(first.as_str())
}

fn mutation_lvalue_base(statement: &str) -> Option<String> {
    let s = statement.trim();
    if contains_word(s, "delete") {
        let pos = find_word_from(s, "delete", 0)?;
        return first_identifier(&s[pos + "delete".len()..]);
    }

    for op in ["+=", "-=", "*=", "/=", "|=", "&=", "^="] {
        if let Some(pos) = find_top_level_operator(s, op) {
            return last_identifier(&s[..pos]);
        }
    }
    if let Some(pos) = s.find("++") {
        return last_identifier(&s[..pos]);
    }
    if let Some(pos) = s.find("--") {
        return last_identifier(&s[..pos]);
    }
    if let Some((lhs, _)) = split_assignment(s) {
        if looks_like_variable_declaration(s) {
            return None;
        }
        return last_identifier(lhs);
    }
    None
}

fn split_assignment(statement: &str) -> Option<(&str, &str)> {
    let pos = find_top_level_operator(statement, "=")?;
    if pos > 0
        && matches!(
            statement.as_bytes().get(pos - 1).copied(),
            Some(b'!' | b'<' | b'>' | b'=')
        )
    {
        return None;
    }
    if statement.as_bytes().get(pos + 1).copied() == Some(b'=') {
        return None;
    }
    Some((&statement[..pos], &statement[pos + 1..]))
}

fn collect_assignments(source: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for statement in split_statements(source) {
        let Some((lhs, rhs)) = split_assignment(&statement) else {
            continue;
        };
        if lhs.contains('[') || lhs.contains('(') && lhs.contains(',') {
            continue;
        }
        if let Some(name) = last_identifier(lhs) {
            out.insert(name, rhs.trim().trim_end_matches(';').to_string());
        }
    }
    out
}

fn parse_function_signature(source: &str) -> FunctionSignature {
    let mut sig = FunctionSignature::default();
    let Some(function_pos) = find_word_from(source, "function", 0) else {
        return sig;
    };
    let after = function_pos + "function".len();
    let Some(name) = first_identifier(&source[after..]) else {
        return sig;
    };
    sig.name = name;
    let Some(open_rel) = source[after..].find('(') else {
        return sig;
    };
    let open = after + open_rel;
    let Some(close) = matching_delimiter(source, open, '(', ')') else {
        return sig;
    };
    sig.params = split_top_level(&source[open + 1..close], ',')
        .into_iter()
        .filter_map(|p| parse_parameter(&p))
        .collect();

    let body_pos = source[close + 1..].find('{').map(|x| close + 1 + x);
    let semicolon_pos = source[close + 1..].find(';').map(|x| close + 1 + x);
    sig.has_body = body_pos.is_some() && (semicolon_pos.is_none() || body_pos < semicolon_pos);
    let header_end = if sig.has_body {
        body_pos.unwrap_or(source.len())
    } else {
        semicolon_pos.unwrap_or(source.len())
    };
    let suffix = &source[close + 1..header_end];
    sig.is_public = contains_word(suffix, "public");
    sig.is_external = contains_word(suffix, "external");
    sig.is_view = contains_word(suffix, "view");
    sig.is_pure = contains_word(suffix, "pure");

    if let Some(rpos) = find_word_from(suffix, "returns", 0) {
        if let Some(open_rel) = suffix[rpos..].find('(') {
            let ropen = rpos + open_rel;
            if let Some(rclose) = matching_delimiter(suffix, ropen, '(', ')') {
                sig.returns = split_top_level(&suffix[ropen + 1..rclose], ',')
                    .into_iter()
                    .filter_map(|p| parse_parameter(&p).map(|x| x.ty))
                    .collect();
            }
        }
    }
    sig
}

fn parse_parameter(text: &str) -> Option<Parameter> {
    let ids = identifier_sequence(text);
    if ids.is_empty() {
        return None;
    }
    let ty = ids.first()?.clone();
    let name = ids
        .iter()
        .rev()
        .find(|id| !is_type_or_location_keyword(id.as_str()) && id.as_str() != ty.as_str())
        .cloned()
        .unwrap_or_default();
    Some(Parameter { ty, name })
}

fn normalize_type(ty: &str) -> String {
    match ty {
        "byte" => "bytes1".into(),
        other => other.to_string(),
    }
}

fn function_body(source: &str) -> Option<&str> {
    let open = source.find('{')?;
    let close = matching_delimiter(source, open, '{', '}')?;
    Some(&source[open + 1..close])
}

fn parse_call_args_at(source: &str, pos: usize) -> Option<Vec<String>> {
    let tail = source.get(pos..)?;
    let open = pos + tail.find('(')?;
    let close = matching_delimiter(source, open, '(', ')')?;
    Some(split_top_level(&source[open + 1..close], ','))
}

fn split_statements(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut p = 0i32;
    let mut b = 0i32;
    let mut in_string = false;
    let mut quote = '\0';
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if in_string {
            if ch == quote && (i == 0 || chars[i - 1] != '\\') {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => p += 1,
            ')' => p -= 1,
            '[' => b += 1,
            ']' => b -= 1,
            ';' if p == 0 && b == 0 => {
                out.push(chars[start..=i].iter().collect());
                start = i + 1;
            }
            _ => {}
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

fn matching_delimiter_backward(
    text: &str,
    close: usize,
    open_ch: char,
    close_ch: char,
) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(close).copied()? as char != close_ch {
        return None;
    }
    let mut depth = 0i32;
    let mut i = close + 1;
    while i > 0 {
        i -= 1;
        let ch = bytes[i] as char;
        if ch == close_ch {
            depth += 1;
        } else if ch == open_ch {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn find_top_level_char(text: &str, target: char) -> Option<usize> {
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
            x if x == target && p == 0 && b == 0 && c == 0 => return Some(i),
            _ => {}
        }
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
    identifier_sequence(text)
        .into_iter()
        .filter(|id| !is_language_keyword(id))
        .collect()
}

fn first_identifier(text: &str) -> Option<String> {
    identifier_sequence(text)
        .into_iter()
        .find(|id| !is_language_keyword(id))
}

fn last_identifier(text: &str) -> Option<String> {
    identifier_sequence(text)
        .into_iter()
        .rev()
        .find(|id| !is_language_keyword(id))
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
            let id = &text[start..i];
            out.push_str(substitutions.get(id).map(String::as_str).unwrap_or(id));
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

fn count_word(text: &str, word: &str) -> usize {
    let mut count = 0;
    let mut from = 0;
    while let Some(pos) = find_word_from(text, word, from) {
        count += 1;
        from = pos + word.len();
    }
    count
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
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
            | "emit"
    )
}

fn is_type_or_location_keyword(s: &str) -> bool {
    is_language_keyword(s)
        || s.starts_with("uint")
        || s.starts_with("int")
        || s.starts_with("bytes")
        || matches!(s, "address" | "bool" | "string" | "mapping")
}

fn is_builtin_identifier(s: &str) -> bool {
    matches!(
        s,
        "msg"
            | "tx"
            | "block"
            | "abi"
            | "address"
            | "keccak256"
            | "ecrecover"
            | "this"
    )
}

#[cfg(test)]
mod eip1271_verification_tests {
    use crate::detect::detector::IssueDetector;

    use super::EIP1271VerificationDetector;

    fn run(path: &str) -> usize {
        let context = crate::detect::test_utils::load_solidity_source_unit(path);
        let mut detector = EIP1271VerificationDetector::default();
        detector.detect(&context).unwrap();
        detector.instances().len()
    }

    #[test]
    fn detects_discarded_staticcall_success() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/IgnoredStaticcallSuccess.sol"),
            1
        );
    }

    #[test]
    fn accepts_strict_low_level_validation() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/SafeStaticcall.sol"),
            0
        );
    }

    #[test]
    fn detects_nonzero_magic_acceptance() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/NonzeroMagic.sol"),
            1
        );
    }

    #[test]
    fn detects_unconditional_magic_implementation() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/UnconditionalMagic.sol"),
            1
        );
    }

    #[test]
    fn accepts_compliant_owner_recovery() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/SafeImplementation.sol"),
            0
        );
    }

    #[test]
    fn detects_user_selected_contract_signer() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/UserSuppliedSigner.sol"),
            1
        );
    }

    #[test]
    fn accepts_allowlisted_contract_signer() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/AllowlistedSigner.sol"),
            0
        );
    }

    #[test]
    fn detects_state_changing_implementation_through_helper() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/StateChangingHelper.sol"),
            1
        );
    }

    #[test]
    fn detects_wrong_erc1271_shape() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/WrongShape.sol"),
            1
        );
    }

    #[test]
    fn detects_helper_that_drops_hash() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/HelperDropsHash.sol"),
            1
        );
    }

    #[test]
    fn detects_unsafe_eoa_fallback() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/UnsafeEOAFallback.sol"),
            1
        );
    }

    #[test]
    fn accepts_signaturechecker_style_branch() {
        assert_eq!(
            run("../tests/contract-playground/src/eip1271-verification/SafeEOAContractBranch.sol"),
            0
        );
    }
}

#[cfg(test)]
mod eip1271_verification_tests {
    use super::*;

    fn model(id: NodeID, scope: NodeID, source: &str) -> FunctionModel {
        let mut member_names = BTreeSet::new();
        if source.contains(".staticcall(") {
            member_names.insert("staticcall".to_string());
        }
        if source.contains(".code.length") {
            member_names.insert("length".to_string());
        }
        FunctionModel {
            id,
            scope,
            source: source.to_string(),
            sig: parse_function_signature(source),
            calls: Vec::new(),
            assignments: collect_assignments(source),
            member_names,
        }
    }

    fn one_model(source: &str) -> (NodeID, BTreeMap<NodeID, FunctionModel>) {
        let id: NodeID = 1;
        let mut models = BTreeMap::new();
        models.insert(id, model(id, 10, source));
        (id, models)
    }

    #[test]
    fn recognizes_canonical_erc1271_shape() {
        let sig = parse_function_signature(
            "function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) { return 0xffffffff; }",
        );
        assert!(is_canonical_erc1271_shape(&sig));

        let wrong = parse_function_signature(
            "function isValidSignature(bytes calldata hash, bytes calldata signature) external view returns (bytes4) { return 0xffffffff; }",
        );
        assert!(!is_canonical_erc1271_shape(&wrong));
    }

    #[test]
    fn catches_gnosis_style_discarded_staticcall_success() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) external view returns (bool) {
                (, bytes memory ret) = signer.staticcall(
                    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
                );
                return ret.length >= 4 && bytes4(ret) == 0x1626ba7e;
            }
        "#;
        let m = model(1, 10, source);
        assert!(caller_low_level_validation_bad(&m));
    }

    #[test]
    fn accepts_strict_low_level_erc1271_call() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) external view returns (bool) {
                (bool success, bytes memory ret) = signer.staticcall(
                    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
                );
                return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
            }
        "#;
        let m = model(1, 10, source);
        assert!(!caller_low_level_validation_bad(&m));
    }

    #[test]
    fn rejects_call_success_without_magic_validation() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) external view returns (bool) {
                (bool success, bytes memory ret) = signer.staticcall(
                    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
                );
                ret;
                return success;
            }
        "#;
        let m = model(1, 10, source);
        assert!(caller_low_level_validation_bad(&m));
    }

    #[test]
    fn rejects_empty_returndata_success_path() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) external view returns (bool) {
                (bool success, bytes memory ret) = signer.staticcall(
                    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
                );
                if (!success) return false;
                if (ret.length == 0) return true;
                return ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
            }
        "#;
        let m = model(1, 10, source);
        assert!(caller_low_level_validation_bad(&m));
    }

    #[test]
    fn catches_unconditional_magic_implementation() {
        let source = r#"
            function isValidSignature(bytes32 hash, bytes calldata signature) external pure returns (bytes4) {
                hash; signature;
                return 0x1626ba7e;
            }
        "#;
        let (id, models) = one_model(source);
        assert!(implementation_ignores_required_inputs(id, &models, MAX_CALL_DEPTH));
    }

    #[test]
    fn accepts_input_dependent_exact_magic_implementation() {
        let source = r#"
            function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
                address recovered = ECDSA.recover(hash, signature);
                return recovered == owner ? 0x1626ba7e : 0xffffffff;
            }
        "#;
        let (id, models) = one_model(source);
        assert!(!implementation_ignores_required_inputs(id, &models, MAX_CALL_DEPTH));
        assert!(!implementation_magic_semantics_bad(id, &models, MAX_CALL_DEPTH));
    }

    #[test]
    fn catches_state_changing_implementation() {
        let source = r#"
            function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
                lastHash = hash;
                address recovered = ECDSA.recover(hash, signature);
                return recovered == owner ? 0x1626ba7e : 0xffffffff;
            }
        "#;
        let (id, models) = one_model(source);
        assert!(implementation_changes_state(id, &models, MAX_CALL_DEPTH));
    }

    #[test]
    fn accepts_direct_interface_exact_magic_check() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
                bytes4 result = IERC1271(signer).isValidSignature(hash, signature);
                return result == 0x1626ba7e;
            }
        "#;
        let m = model(1, 10, source);
        assert!(!caller_direct_input_forwarding_bad(&m));
        assert!(!caller_direct_magic_validation_bad(&m));
    }

    #[test]
    fn rejects_direct_interface_nonzero_check() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
                bytes4 result = IERC1271(signer).isValidSignature(hash, signature);
                return result != bytes4(0);
            }
        "#;
        let m = model(1, 10, source);
        assert!(caller_direct_magic_validation_bad(&m));
    }

    #[test]
    fn catches_permissive_eoa_branch() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
                if (signer.code.length == 0) return true;
                (bool success, bytes memory ret) = signer.staticcall(
                    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
                );
                return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
            }
        "#;
        let m = model(1, 10, source);
        assert!(caller_eoa_contract_branch_bad(&m));
    }

    #[test]
    fn accepts_signaturechecker_style_branch() {
        let source = r#"
            function check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
                if (signer.code.length == 0) {
                    return ECDSA.recover(hash, signature) == signer;
                }
                (bool success, bytes memory ret) = signer.staticcall(
                    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
                );
                return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
            }
        "#;
        let m = model(1, 10, source);
        assert!(!caller_eoa_contract_branch_bad(&m));
        assert!(!caller_low_level_validation_bad(&m));
    }
}
