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
    collect_assignments, compact, expand_expression, find_top_level_operator, function_name,
    identifier_sequence, identifiers_in_text, is_public_or_external, matching_delimiter,
    parse_call_args_at, split_statements, split_top_level, substitute_identifiers, SrcSpan,
};

/// Detects semantic EIP-712 implementation defects on signature-authorized Solidity paths.
///
/// The detector deliberately does not require every optional EIP-712 domain field. Instead it
/// reasons about four classes:
/// 1. malformed or attacker-controlled domain construction;
/// 2. TYPEHASH / encodeData inconsistencies;
/// 3. malformed final `\x19\x01 || domainSeparator || structHash` construction; and
/// 4. security-sensitive runtime values that are not committed to the authenticated struct.
///
/// Aderyn v0.6.8 does not expose SSA/CFG/dominance APIs to detectors. The implementation therefore
/// combines Aderyn AST discovery (function/contract spans, identifiers, member accesses and
/// referenced declarations) with a bounded Solidity-aware source/data-flow layer. Production logic
/// never references benchmark IDs, filenames, contract names or benchmark-specific field names.
#[derive(Default)]
pub struct EIP712ImplementationDetector {
    found_instances: BTreeMap<(String, usize, String), NodeID>,
}

#[derive(Debug, Clone)]
struct Parameter {
    ty: String,
    name: String,
}

#[derive(Debug, Clone)]
struct CallSite {
    callee: NodeID,
    name: String,
    args: Vec<String>,
    pos: usize,
}

#[derive(Debug, Clone, Default)]
struct AuthSummary {
    signature_verification: bool,
    digest_expressions: Vec<String>,
    authenticated_roots: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct FunctionModel {
    id: NodeID,
    source: String,
    contract_source: String,
    file: usize,
    entry_point: bool,
    parameters: Vec<Parameter>,
    assignments: HashMap<String, String>,
    calls: Vec<CallSite>,
    direct_auth: AuthSummary,
    signature_positions: Vec<usize>,
}

#[derive(Debug, Clone)]
struct TypeField {
    ty: String,
    name: String,
}

#[derive(Debug, Clone)]
struct TypeDecl {
    name: String,
    fields: Vec<TypeField>,
}

#[derive(Debug, Clone)]
struct TypeHashDefinition {
    encoded_type: String,
    declarations: Vec<TypeDecl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestStatus {
    Correct,
    Incorrect,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypedRole {
    Domain,
    Struct,
    Unknown,
}

#[derive(Debug, Clone)]
struct WriteFact {
    lhs: String,
    rhs: String,
    pos: usize,
}

impl IssueDetector for EIP712ImplementationDetector {
    fn detect(&mut self, context: &WorkspaceContext) -> Result<bool, Box<dyn Error>> {
        let models = build_models(context);
        if models.is_empty() {
            return Ok(false);
        }

        let auth = propagate_auth_summaries(&models);
        let mut vulnerable = BTreeSet::new();

        for model in models.values().filter(|m| m.entry_point) {
            let summary = auth.get(&model.id).cloned().unwrap_or_default();
            if !summary.signature_verification || !is_eip712_candidate(model, &summary, &models) {
                continue;
            }

            let reachable = reachable_functions(model.id, &models, 4);

            let bad_domain = domain_construction_is_suspicious(model, &summary, &models, &reachable);
            let bad_struct = structured_encoding_is_suspicious(model, &models, &reachable);
            let bad_final = final_digest_is_suspicious(model, &summary, &models);
            let unsigned_runtime = unsigned_runtime_binding_is_suspicious(
                model,
                &summary,
                &models,
                &reachable,
            );

            if bad_domain || bad_struct || bad_final || unsigned_runtime {
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
        // Aderyn v0.6.8 exposes High/Low severities. This detector reports semantic authorization
        // defects rather than merely the presence of manual hashing, so High is appropriate.
        IssueSeverity::High
    }

    fn title(&self) -> String {
        String::from("EIP-712 Implementation Vulnerability")
    }

    fn description(&self) -> String {
        String::from(
            "An EIP-712 signature-authorized operation constructs its signing domain, structured \
             data hash, final typed-data digest, or runtime authorization boundary incorrectly. \
             EIP-712 requires hashStruct(message) = keccak256(typeHash || encodeData(message)) and \
             the final digest keccak256(\\\"\\x19\\x01\\\" || domainSeparator || structHash). \
             Dynamic string/bytes members and arrays/nested structs require their EIP-712-specific \
             hashed representation. Domain fields are optional, so absence of chainId or \
             verifyingContract alone is not reported; however attacker-controlled domain material, \
             inconsistent domain field encoding, stale chain-dependent caches, or an incorrect \
             verifying-contract value can invalidate the intended domain separation. Finally, every \
             security-sensitive runtime value controlled by the signed operation should be committed \
             to the signed typed data. Use a reviewed EIP-712 domain/final-hash implementation, keep \
             TYPEHASH definitions synchronized with encodeData, hash dynamic/reference members per \
             EIP-712, and bind all execution-critical parameters to the signed struct.",
        )
    }

    fn instances(&self) -> BTreeMap<(String, usize, String), NodeID> {
        self.found_instances.clone()
    }

    fn name(&self) -> String {
        format!("{}", IssueDetectorNamePool::EIP712Implementation)
    }
}

fn build_models(context: &WorkspaceContext) -> BTreeMap<NodeID, FunctionModel> {
    let function_spans: Vec<(NodeID, SrcSpan)> = context
        .function_definitions()
        .into_iter()
        .filter_map(|f| SrcSpan::parse(&f.src).map(|span| (f.id, span)))
        .collect();
    let function_ids: HashSet<NodeID> = function_spans.iter().map(|(id, _)| *id).collect();

    // Contract-level source is needed to validate TYPEHASH and domain declarations that live
    // outside function bodies. `contract_definitions()` follows the same v0.6.8 extraction API as
    // `function_definitions()` and returns a Vec, hence the explicit `.into_iter()` where needed.
    let contract_spans: Vec<(NodeID, SrcSpan)> = context
        .contract_definitions()
        .into_iter()
        .filter_map(|c| SrcSpan::parse(&c.src).map(|span| (c.id, span)))
        .collect();
    let mut contract_source_by_id = HashMap::new();
    for contract in context.contract_definitions() {
        contract_source_by_id.insert(contract.id, contract.peek(context).unwrap_or_default());
    }

    let span_by_id: HashMap<NodeID, SrcSpan> = function_spans.iter().copied().collect();
    let mut source_by_id = HashMap::new();
    let mut parameters_by_id = HashMap::new();
    let mut functions_by_name: HashMap<String, Vec<NodeID>> = HashMap::new();
    let mut functions_by_file_and_name: HashMap<(usize, String), Vec<NodeID>> = HashMap::new();

    for function in context.function_definitions() {
        let source = function.peek(context).unwrap_or_default();
        let parameters = parse_parameters(&source);
        if let Some(name) = function_name(&source) {
            functions_by_name.entry(name.clone()).or_default().push(function.id);
            if let Some(span) = span_by_id.get(&function.id) {
                functions_by_file_and_name
                    .entry((span.file, name))
                    .or_default()
                    .push(function.id);
            }
        }
        parameters_by_id.insert(function.id, parameters);
        source_by_id.insert(function.id, source);
    }

    let mut signature_calls: HashMap<NodeID, Vec<(usize, String, Vec<String>)>> = HashMap::new();

    // Direct built-in recovery is discovered semantically through Aderyn's Identifier AST.
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
        let Some(source) = source_by_id.get(&function_id) else {
            continue;
        };
        let local_pos = node_span.start.saturating_sub(function_span.start);
        let args = parse_call_args_at(source, local_pos).unwrap_or_default();
        signature_calls
            .entry(function_id)
            .or_default()
            .push((local_pos, "ecrecover".into(), args));
    }

    // Library/member recovery forms are discovered through MemberAccess AST nodes. The accessor is
    // intentionally `member_accesss()` in the user's exact v0.6.8 checkout (three 's' characters),
    // matching the compatibility fix already required by SignatureReplayDetector.
    for member in context.member_accesss() {
        let name = member.member_name.as_str();
        if !is_signature_member_name(name) {
            continue;
        }
        let Some(node_span) = SrcSpan::parse(&member.src) else {
            continue;
        };
        let Some((function_id, function_span)) = enclosing_function(node_span, &function_spans)
        else {
            continue;
        };
        let Some(source) = source_by_id.get(&function_id) else {
            continue;
        };
        let local_pos = node_span.start.saturating_sub(function_span.start);
        let args = parse_call_args_at(source, local_pos).unwrap_or_default();
        if signature_member_shape_is_plausible(name, &args) {
            signature_calls
                .entry(function_id)
                .or_default()
                .push((local_pos, name.to_string(), args));
        }
    }

    let mut calls_by_caller: HashMap<NodeID, Vec<CallSite>> = HashMap::new();

    // Normal internal calls: v0.6.8 exposes `referenced_declaration` as a field, not a method.
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
        let Some((caller, caller_span)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        if caller == callee {
            continue;
        }
        let Some(source) = source_by_id.get(&caller) else {
            continue;
        };
        let local_pos = node_span.start.saturating_sub(caller_span.start);
        let args = parse_call_args_at(source, local_pos).unwrap_or_default();
        calls_by_caller.entry(caller).or_default().push(CallSite {
            callee,
            name: identifier.name.clone(),
            args,
            pos: local_pos,
        });
    }

    // Member/library calls do not always expose a referenced-declaration API in the exact checkout.
    // Resolve only when a function name is unique in the same source file, or globally unique.
    for member in context.member_accesss() {
        let Some(node_span) = SrcSpan::parse(&member.src) else {
            continue;
        };
        let Some((caller, caller_span)) = enclosing_function(node_span, &function_spans) else {
            continue;
        };
        let name = member.member_name.clone();
        let same_file = functions_by_file_and_name
            .get(&(node_span.file, name.clone()))
            .cloned()
            .unwrap_or_default();
        let global = functions_by_name.get(&name).cloned().unwrap_or_default();
        let callee = if same_file.len() == 1 {
            same_file.first().copied()
        } else if global.len() == 1 {
            global.first().copied()
        } else {
            None
        };
        let Some(callee) = callee else {
            continue;
        };
        if callee == caller {
            continue;
        }
        let Some(source) = source_by_id.get(&caller) else {
            continue;
        };
        let local_pos = node_span.start.saturating_sub(caller_span.start);
        let args = parse_call_args_at(source, local_pos).unwrap_or_default();
        if calls_by_caller
            .get(&caller)
            .is_some_and(|xs| xs.iter().any(|x| x.callee == callee && x.pos == local_pos))
        {
            continue;
        }
        calls_by_caller.entry(caller).or_default().push(CallSite {
            callee,
            name,
            args,
            pos: local_pos,
        });
    }

    let mut models = BTreeMap::new();
    for function in context.function_definitions() {
        let Some(span) = span_by_id.get(&function.id).copied() else {
            continue;
        };
        let source = source_by_id.get(&function.id).cloned().unwrap_or_default();
        let parameters = parameters_by_id.get(&function.id).cloned().unwrap_or_default();
        let assignments = collect_assignments(&source);
        let direct_calls = signature_calls.get(&function.id).cloned().unwrap_or_default();
        let direct_auth = summarize_direct_signature_calls(&source, &parameters, &assignments, &direct_calls);
        let signature_positions = direct_calls.iter().map(|(pos, _, _)| *pos).collect();

        let contract_source = enclosing_contract(span, &contract_spans)
            .and_then(|(id, _)| contract_source_by_id.get(&id).cloned())
            .unwrap_or_default();

        models.insert(
            function.id,
            FunctionModel {
                id: function.id,
                source,
                contract_source,
                file: span.file,
                entry_point: is_public_or_external(source_by_id.get(&function.id).map(String::as_str).unwrap_or("")),
                parameters,
                assignments,
                calls: calls_by_caller.remove(&function.id).unwrap_or_default(),
                direct_auth,
                signature_positions,
            },
        );
    }

    models
}

fn summarize_direct_signature_calls(
    source: &str,
    parameters: &[Parameter],
    assignments: &HashMap<String, String>,
    calls: &[(usize, String, Vec<String>)],
) -> AuthSummary {
    let mut out = AuthSummary::default();
    for (_, name, args) in calls {
        let Some(digest) = signature_digest_argument(name, args) else {
            continue;
        };
        let expanded = expand_expression(digest, assignments, 6);
        out.signature_verification = true;
        if !out.digest_expressions.iter().any(|x| compact(x) == compact(&expanded)) {
            out.digest_expressions.push(expanded.clone());
        }
        for parameter in parameters {
            if expression_depends_on(&expanded, &parameter.name) {
                out.authenticated_roots.insert(parameter.name.clone());
            }
        }
    }

    // Source fallback for reviewed/common wrappers that may not be represented as MemberAccess in
    // every compiler AST shape. It is used only to establish a signature sink and still requires a
    // parsable digest argument; it never classifies EIP-712 correctness by name alone.
    if !out.signature_verification {
        for name in [
            "ecrecover",
            "recoverChecked",
            "recover",
            "tryRecover",
            "isValidSignatureNow",
            "isValidSignature",
        ] {
            let mut from = 0usize;
            while let Some(pos) = find_call_name(source, name, from) {
                let args = parse_call_args_at(source, pos).unwrap_or_default();
                if let Some(digest) = signature_digest_argument(name, &args) {
                    let expanded = expand_expression(digest, assignments, 6);
                    out.signature_verification = true;
                    out.digest_expressions.push(expanded.clone());
                    for parameter in parameters {
                        if expression_depends_on(&expanded, &parameter.name) {
                            out.authenticated_roots.insert(parameter.name.clone());
                        }
                    }
                }
                from = pos.saturating_add(name.len());
                if from >= source.len() {
                    break;
                }
            }
        }
    }

    out
}

fn propagate_auth_summaries(models: &BTreeMap<NodeID, FunctionModel>) -> BTreeMap<NodeID, AuthSummary> {
    let mut summaries: BTreeMap<NodeID, AuthSummary> = models
        .iter()
        .map(|(id, model)| (*id, model.direct_auth.clone()))
        .collect();

    for _ in 0..6 {
        let previous = summaries.clone();
        let mut changed = false;
        for model in models.values() {
            let mut current = previous.get(&model.id).cloned().unwrap_or_default();
            for call in &model.calls {
                let Some(callee_model) = models.get(&call.callee) else {
                    continue;
                };
                let Some(callee_summary) = previous.get(&call.callee) else {
                    continue;
                };
                if !callee_summary.signature_verification {
                    continue;
                }
                current.signature_verification = true;
                let substitutions = parameter_substitutions(&callee_model.parameters, &call.args);
                for digest in &callee_summary.digest_expressions {
                    let instantiated = substitute_identifiers(digest, &substitutions);
                    let expanded = expand_expression(&instantiated, &model.assignments, 6);
                    if !current.digest_expressions.iter().any(|x| compact(x) == compact(&expanded)) {
                        current.digest_expressions.push(expanded.clone());
                        changed = true;
                    }
                    for parameter in &model.parameters {
                        if expression_depends_on(&expanded, &parameter.name)
                            && current.authenticated_roots.insert(parameter.name.clone())
                        {
                            changed = true;
                        }
                    }
                }
            }
            if current.signature_verification
                != previous.get(&model.id).is_some_and(|x| x.signature_verification)
            {
                changed = true;
            }
            summaries.insert(model.id, current);
        }
        if !changed {
            break;
        }
    }

    summaries
}

fn is_eip712_candidate(
    model: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    let markers = [
        "EIP712Domain(",
        "_hashTypedDataV4",
        "_hashTypedData(",
        "typedDataHash(",
        "toTypedDataHash(",
        "\\x19\\x01",
        "0x1901",
        "hex\"1901\"",
    ];
    if markers.iter().any(|m| model.source.contains(m) || model.contract_source.contains(m)) {
        return true;
    }
    if auth.digest_expressions.iter().any(|d| markers.iter().any(|m| d.contains(m))) {
        return true;
    }
    reachable_functions(model.id, models, 3).into_iter().any(|id| {
        models.get(&id).is_some_and(|m| markers.iter().any(|x| m.source.contains(x)))
    })
}

fn domain_construction_is_suspicious(
    model: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
    reachable: &BTreeSet<NodeID>,
) -> bool {
    let definitions = parse_typehash_definitions(&model.contract_source);
    let domain_defs: HashMap<String, TypeHashDefinition> = definitions
        .iter()
        .filter(|(_, d)| d.declarations.first().is_some_and(|x| x.name == "EIP712Domain"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for id in reachable {
        let Some(function) = models.get(id) else {
            continue;
        };
        if domain_encode_has_mismatch(function, &domain_defs)
            || domain_helper_binding_is_suspicious(function)
        {
            return true;
        }
    }

    // The EIP allows optional domain fields. We therefore do NOT flag a domain merely because it
    // omits chainId or verifyingContract. Findings require positive evidence of unsafe material.
    for digest in &auth.digest_expressions {
        if final_domain_argument_is_untrusted(digest, model, models) {
            return true;
        }
    }

    if stale_chain_dependent_domain_cache(&model.contract_source) {
        return true;
    }

    if stale_mutable_version_domain(&model.contract_source) {
        return true;
    }

    false
}

fn domain_encode_has_mismatch(
    function: &FunctionModel,
    domain_defs: &HashMap<String, TypeHashDefinition>,
) -> bool {
    if domain_defs.is_empty() {
        return false;
    }
    for encoding in find_hash_encodings(&function.source) {
        if encoding.args.is_empty() {
            continue;
        }
        let key = simple_identifier(&encoding.args[0]);
        let Some(key) = key else {
            continue;
        };
        let Some(definition) = domain_defs.get(key) else {
            continue;
        };
        let Some(primary) = definition.declarations.first() else {
            continue;
        };
        if encoding.packed || encoding.args.len().saturating_sub(1) != primary.fields.len() {
            return true;
        }
        for (field, expression) in primary.fields.iter().zip(encoding.args.iter().skip(1)) {
            if field.ty == "string" && !expression_is_hashed_dynamic(expression, function, None) {
                return true;
            }
            match field.name.as_str() {
                "chainId" => {
                    if looks_like_numeric_literal(expression)
                        || function_parameter(function, expression).is_some()
                        || expression.contains("address(this)")
                        || expression.contains("msg.sender")
                        || expression.contains("tx.origin")
                    {
                        return true;
                    }
                }
                "verifyingContract" => {
                    if expression.contains("msg.sender") || expression.contains("tx.origin") {
                        return true;
                    }
                    if function_parameter(function, expression).is_some() {
                        return true;
                    }
                    if simple_identifier(expression).is_some_and(|id| {
                        state_value_is_constructor_or_external_input(&function.contract_source, id)
                    }) {
                        return true;
                    }
                    if expression.contains("block.chainid") {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn domain_helper_binding_is_suspicious(function: &FunctionModel) -> bool {
    let source = &function.source;
    let mut from = 0usize;
    while from < source.len() {
        let Some(rel) = source[from..].find("domain") else {
            break;
        };
        let pos = from + rel;
        let Some(args) = parse_call_args_at(source, pos) else {
            from = pos.saturating_add("domain".len());
            continue;
        };
        if args.len() >= 3 {
            let verifier = args[2].trim();
            if verifier.contains("msg.sender")
                || verifier.contains("tx.origin")
                || function_parameter(function, verifier).is_some()
                || simple_identifier(verifier).is_some_and(|id| {
                    state_value_is_constructor_or_external_input(&function.contract_source, id)
                })
            {
                return true;
            }
        }
        from = pos.saturating_add("domain".len());
    }
    false
}

fn final_domain_argument_is_untrusted(
    digest: &str,
    model: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    let resolved = resolve_simple_alias(digest, &model.assignments, 4);
    if let Some((name, args)) = root_call(&resolved) {
        if is_canonical_typed_hash_helper(&name) && args.len() >= 2 {
            let domain = args[0].trim();
            if expression_has_untrusted_root(domain, model)
                || looks_like_external_domain_provider(domain)
            {
                return true;
            }
        }
        if name == "keccak256" && args.len() == 1 {
            if let Some((encoder, pieces)) = root_call(&args[0]) {
                if encoder == "abi.encodePacked"
                    && pieces.len() == 3
                    && is_canonical_1901_prefix(&pieces[0], model)
                {
                    let domain = pieces[1].trim();
                    if expression_has_untrusted_root(domain, model)
                        || looks_like_external_domain_provider(domain)
                    {
                        return true;
                    }
                }
            }
        }
    }

    // If an internal typed-hash wrapper is used, instantiate its return expression and inspect the
    // resulting canonical helper/domain argument.
    if let Some((name, args)) = root_call(&resolved) {
        if let Some(callee_id) = resolve_function_name(model, &name, models) {
            if let Some(callee) = models.get(&callee_id) {
                if let Some(ret) = first_return_expression(&callee.source) {
                    let substitutions = parameter_substitutions(&callee.parameters, &args);
                    let instantiated = substitute_identifiers(&ret, &substitutions);
                    return final_domain_argument_is_untrusted(&instantiated, model, models);
                }
            }
        }
    }

    false
}

fn stale_chain_dependent_domain_cache(contract_source: &str) -> bool {
    // Detect an immutable/cached domain value initialized from a chain-dependent construction and
    // later used without a chain/address cache invalidation check. This mirrors the security
    // property of OpenZeppelin's `_domainSeparatorV4`, not a particular variable name.
    let constructors = functions_named(contract_source, "constructor");
    if constructors.is_empty() {
        return false;
    }
    let has_runtime_invalidation = contract_source.contains("block.chainid ==")
        || contract_source.contains("block.chainid==")
        || contract_source.contains("== block.chainid")
        || contract_source.contains("==block.chainid")
        || contract_source.contains("address(this) ==")
        || contract_source.contains("address(this)==");
    if has_runtime_invalidation {
        return false;
    }

    for constructor in constructors {
        for statement in split_statements(&constructor) {
            let Some(eq) = find_top_level_operator(&statement, "=") else {
                continue;
            };
            let lhs = statement[..eq].trim();
            let rhs = statement[eq + 1..].trim();
            let Some(name) = last_non_keyword_identifier(lhs) else {
                continue;
            };
            if !declaration_has_word(contract_source, &name, "immutable") {
                continue;
            }
            let chain_dependent = rhs.contains("block.chainid")
                || rhs.contains("domain(")
                || rhs.contains("_buildDomain")
                || rhs.contains("_domainSeparator");
            if chain_dependent && contract_source.matches(&name).count() >= 2 {
                return true;
            }
        }
    }
    false
}

fn stale_mutable_version_domain(contract_source: &str) -> bool {
    // Conservative upgrade/version check: a mutable hash derived from a string version is updated
    // by an externally reachable function while the actual domain used for signing remains cached
    // in an immutable value. Merely having a version field is not suspicious.
    if !contract_source.contains("EIP712Domain(") && !contract_source.contains("domain(") {
        return false;
    }
    let has_cached_domain = contract_source.contains("immutable")
        && (contract_source.contains("DOMAIN_SEPARATOR") || contract_source.contains("cachedDomain"));
    if !has_cached_domain {
        return false;
    }
    for (_, function, _, _) in parse_functions_from_source(contract_source) {
        if !is_public_or_external(&function) || !function.contains("string") {
            continue;
        }
        if function.contains("keccak256(bytes(") && function.contains('=') {
            return true;
        }
    }
    false
}

fn structured_encoding_is_suspicious(
    model: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    reachable: &BTreeSet<NodeID>,
) -> bool {
    let definitions = parse_typehash_definitions(&model.contract_source);
    if definitions.is_empty() {
        return false;
    }

    for id in reachable {
        let Some(function) = models.get(id) else {
            continue;
        };
        for encoding in find_hash_encodings(&function.source) {
            if encoding.args.is_empty() {
                continue;
            }
            let Some(typehash_name) = simple_identifier(&encoding.args[0]) else {
                continue;
            };
            let Some(definition) = definitions.get(typehash_name) else {
                continue;
            };
            let Some(primary) = definition.declarations.first() else {
                continue;
            };
            if primary.name == "EIP712Domain" {
                continue;
            }
            if structured_hash_mismatch(function, definition, &encoding, models) {
                return true;
            }
        }
    }

    false
}

#[derive(Debug, Clone)]
struct HashEncoding {
    packed: bool,
    args: Vec<String>,
}

fn structured_hash_mismatch(
    function: &FunctionModel,
    definition: &TypeHashDefinition,
    encoding: &HashEncoding,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    let Some(primary) = definition.declarations.first() else {
        return false;
    };
    if encoding.packed {
        return true;
    }
    let values = &encoding.args[1..];
    if values.len() != primary.fields.len() {
        return true;
    }

    for (field, value) in primary.fields.iter().zip(values.iter()) {
        if let Some(parameter) = function_parameter(function, value) {
            if !types_compatible(&field.ty, &parameter.ty) {
                return true;
            }
        }

        if is_dynamic_scalar_type(&field.ty) {
            if !expression_is_hashed_dynamic(value, function, Some(models)) {
                return true;
            }
        } else if is_array_type(&field.ty) {
            if !expression_is_eip712_array_hash(value, function, models) {
                return true;
            }
        } else if is_custom_struct_type(&field.ty) {
            if !expression_is_struct_hash(value, function, models) {
                return true;
            }
        }
    }

    let referenced = referenced_custom_types(primary);
    if !referenced.is_empty() {
        let appended: Vec<String> = definition
            .declarations
            .iter()
            .skip(1)
            .map(|x| x.name.clone())
            .collect();
        if referenced.iter().any(|name| !appended.contains(name)) {
            return true;
        }
        let mut sorted = appended.clone();
        sorted.sort();
        if sorted != appended {
            return true;
        }
    }

    false
}

fn final_digest_is_suspicious(
    model: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    let mut saw_correct = false;
    let mut saw_incorrect = false;
    for digest in &auth.digest_expressions {
        match classify_typed_digest(digest, model, models, 6) {
            DigestStatus::Correct => saw_correct = true,
            DigestStatus::Incorrect => saw_incorrect = true,
            DigestStatus::Unknown => {}
        }
    }
    // Prefer precision: unknown manual wrappers are not reported solely because the detector cannot
    // prove them correct. A positive malformed construction is required.
    saw_incorrect && !saw_correct
}

fn classify_typed_digest(
    expression: &str,
    model: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
    depth: usize,
) -> DigestStatus {
    if depth == 0 {
        return DigestStatus::Unknown;
    }
    let resolved = resolve_simple_alias(expression, &model.assignments, 5);
    let stripped = strip_outer_parentheses(resolved.trim());

    if let Some(parameter) = function_parameter(model, stripped) {
        if parameter.ty.contains("bytes32") {
            return DigestStatus::Incorrect;
        }
    }

    let Some((name, args)) = root_call(stripped) else {
        return if expression_role(stripped, model) != TypedRole::Unknown {
            DigestStatus::Incorrect
        } else {
            DigestStatus::Unknown
        };
    };

    if is_canonical_typed_hash_helper(&name) {
        return if canonical_typed_helper_arity(&name, args.len()) {
            DigestStatus::Correct
        } else {
            DigestStatus::Incorrect
        };
    }

    if name == "keccak256" {
        if args.len() != 1 {
            return DigestStatus::Incorrect;
        }
        let inner = strip_outer_parentheses(args[0].trim());
        let Some((encoder, pieces)) = root_call(inner) else {
            return DigestStatus::Incorrect;
        };
        if encoder == "abi.encode" {
            return DigestStatus::Incorrect;
        }
        if encoder != "abi.encodePacked" {
            return DigestStatus::Incorrect;
        }
        if pieces.len() != 3 || !is_canonical_1901_prefix(&pieces[0], model) {
            return DigestStatus::Incorrect;
        }

        let second_role = expression_role(&pieces[1], model);
        let third_role = expression_role(&pieces[2], model);
        if second_role == TypedRole::Struct && third_role == TypedRole::Domain {
            return DigestStatus::Incorrect;
        }
        if expression_double_hashes_role(&pieces[1], model, TypedRole::Domain)
            || expression_double_hashes_role(&pieces[2], model, TypedRole::Struct)
        {
            return DigestStatus::Incorrect;
        }
        if second_role == TypedRole::Domain && third_role == TypedRole::Struct {
            return DigestStatus::Correct;
        }
        // The exact framing is correct even when helper names obscure roles. Do not invent a false
        // positive merely because the local variables use nonstandard names.
        return DigestStatus::Correct;
    }

    if let Some(callee_id) = resolve_function_name(model, &name, models) {
        let Some(callee) = models.get(&callee_id) else {
            return DigestStatus::Unknown;
        };
        let Some(ret) = first_return_expression(&callee.source) else {
            return DigestStatus::Unknown;
        };
        let substitutions = parameter_substitutions(&callee.parameters, &args);
        let instantiated = substitute_identifiers(&ret, &substitutions);
        return classify_typed_digest(&instantiated, model, models, depth - 1);
    }

    // Explicit EIP-191 framing other than version 0x01 is a positive malformed-EIP712 signal.
    let lower = compact(stripped).to_ascii_lowercase();
    if lower.contains("ethereumsignedmessage")
        || lower.contains("\\x19\\x00")
        || lower.contains("0x1900")
    {
        return DigestStatus::Incorrect;
    }

    DigestStatus::Unknown
}

fn unsigned_runtime_binding_is_suspicious(
    model: &FunctionModel,
    auth: &AuthSummary,
    models: &BTreeMap<NodeID, FunctionModel>,
    _reachable: &BTreeSet<NodeID>,
) -> bool {
    let parameter_names: BTreeSet<String> = model.parameters.iter().map(|p| p.name.clone()).collect();
    let unsigned: BTreeSet<String> = parameter_names
        .difference(&auth.authenticated_roots)
        .filter(|name| !is_signature_transport_parameter(name, model))
        .cloned()
        .collect();
    if unsigned.is_empty() {
        return false;
    }

    let sink_pos = model.signature_positions.iter().copied().min().unwrap_or(0);
    let writes = parse_write_facts(&model.source, sink_pos);
    for write in &writes {
        let unsigned_roots = roots_from_set(&write.rhs, &unsigned);
        if !unsigned_roots.is_empty() && is_persistent_lvalue(model, &write.lhs) {
            return true;
        }
    }

    // Low-level/external execution whose target or payload is unsigned is security-sensitive even if
    // there is no state write. This catches realistic arbitrary-target / calldata wrapper patterns.
    if unsigned_flows_to_external_call(&model.source, sink_pos, &unsigned) {
        return true;
    }

    // Propagate unsigned arguments into internal helpers only when the helper has an observable
    // persistent write. Pure/view/hash helpers are ignored.
    for call in &model.calls {
        if call.pos <= sink_pos {
            continue;
        }
        let Some(callee) = models.get(&call.callee) else {
            continue;
        };
        if !function_has_persistent_write(callee) {
            continue;
        }
        for arg in &call.args {
            if !roots_from_set(arg, &unsigned).is_empty() {
                return true;
            }
        }
    }

    false
}

fn is_signature_transport_parameter(name: &str, model: &FunctionModel) -> bool {
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "v" | "r" | "s" | "signature" | "sig") {
        return true;
    }
    model.parameters.iter().find(|p| p.name == name).is_some_and(|p| {
        let ty = compact(&p.ty);
        (ty == "uint8" && lower.contains('v'))
            || (ty == "bytes32" && (lower == "r" || lower == "s"))
            || (ty.starts_with("bytes") && lower.contains("signature"))
    })
}

fn parse_parameters(source: &str) -> Vec<Parameter> {
    let Some(function_pos) = source.find("function") else {
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
            let ids = identifier_sequence(&raw);
            let name = ids.last()?.clone();
            let name_pos = raw.rfind(&name)?;
            let mut ty = raw[..name_pos].trim().to_string();
            for location in ["calldata", "memory", "storage", "payable"] {
                ty = remove_word(&ty, location);
            }
            Some(Parameter {
                ty: ty.trim().to_string(),
                name,
            })
        })
        .collect()
}

fn parameter_substitutions(parameters: &[Parameter], args: &[String]) -> HashMap<String, String> {
    parameters
        .iter()
        .zip(args.iter())
        .map(|(p, a)| (p.name.clone(), a.clone()))
        .collect()
}

fn function_parameter<'a>(model: &'a FunctionModel, expression: &str) -> Option<&'a Parameter> {
    let identifier = simple_identifier(expression)?;
    model.parameters.iter().find(|p| p.name == identifier)
}

fn signature_digest_argument<'a>(name: &str, args: &'a [String]) -> Option<&'a str> {
    match name {
        "ecrecover" | "recover" | "tryRecover" | "recoverChecked" => args.first().map(String::as_str),
        "isValidSignatureNow" => {
            if args.len() >= 3 {
                args.get(1).map(String::as_str)
            } else {
                args.first().map(String::as_str)
            }
        }
        "isValidSignature" => args.first().map(String::as_str),
        "isValid" => {
            if args.len() >= 3 {
                args.get(1).map(String::as_str)
            } else {
                args.first().map(String::as_str)
            }
        }
        _ => None,
    }
}

fn is_signature_member_name(name: &str) -> bool {
    matches!(
        name,
        "recover"
            | "tryRecover"
            | "recoverChecked"
            | "isValidSignature"
            | "isValidSignatureNow"
            | "isValid"
    )
}

fn signature_member_shape_is_plausible(name: &str, args: &[String]) -> bool {
    match name {
        "recover" | "tryRecover" | "recoverChecked" => args.len() >= 2,
        "isValidSignature" => args.len() >= 2,
        "isValidSignatureNow" | "isValid" => args.len() >= 2,
        _ => false,
    }
}

fn reachable_functions(
    root: NodeID,
    models: &BTreeMap<NodeID, FunctionModel>,
    max_depth: usize,
) -> BTreeSet<NodeID> {
    let mut seen = BTreeSet::from([root]);
    let mut frontier = BTreeSet::from([root]);
    for _ in 0..max_depth {
        let mut next = BTreeSet::new();
        for id in frontier {
            if let Some(model) = models.get(&id) {
                for call in &model.calls {
                    if seen.insert(call.callee) {
                        next.insert(call.callee);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    seen
}

fn enclosing_function(node: SrcSpan, functions: &[(NodeID, SrcSpan)]) -> Option<(NodeID, SrcSpan)> {
    functions
        .iter()
        .filter(|(_, span)| span.contains(node))
        .min_by_key(|(_, span)| span.len)
        .copied()
}

fn enclosing_contract(node: SrcSpan, contracts: &[(NodeID, SrcSpan)]) -> Option<(NodeID, SrcSpan)> {
    contracts
        .iter()
        .filter(|(_, span)| span.contains(node))
        .min_by_key(|(_, span)| span.len)
        .copied()
}

fn find_call_name(source: &str, name: &str, from: usize) -> Option<usize> {
    let mut offset = from;
    while offset < source.len() {
        let rel = source[offset..].find(name)?;
        let pos = offset + rel;
        let before_ok = pos == 0
            || !source
                .as_bytes()
                .get(pos - 1)
                .copied()
                .is_some_and(|c| c == b'_' || c.is_ascii_alphanumeric());
        let mut after = pos + name.len();
        while source.as_bytes().get(after).copied().is_some_and(|c| c.is_ascii_whitespace()) {
            after += 1;
        }
        let after_ok = source.as_bytes().get(after).copied() == Some(b'(');
        if before_ok && after_ok {
            return Some(pos);
        }
        offset = pos + name.len();
    }
    None
}

fn expression_depends_on(expression: &str, identifier: &str) -> bool {
    identifiers_in_text(expression).contains(identifier)
}

fn roots_from_set(expression: &str, candidates: &BTreeSet<String>) -> BTreeSet<String> {
    let ids = identifiers_in_text(expression);
    candidates.intersection(&ids).cloned().collect()
}

fn resolve_simple_alias(
    expression: &str,
    assignments: &HashMap<String, String>,
    depth: usize,
) -> String {
    if depth == 0 {
        return expression.to_string();
    }
    let stripped = strip_outer_parentheses(expression.trim());
    if let Some(id) = simple_identifier(stripped) {
        if let Some(rhs) = assignments.get(id) {
            return resolve_simple_alias(rhs, assignments, depth - 1);
        }
    }
    expression.to_string()
}

fn simple_identifier(text: &str) -> Option<&str> {
    let t = strip_outer_parentheses(text.trim());
    if t.is_empty() {
        return None;
    }
    let bytes = t.as_bytes();
    if !(bytes[0] == b'_' || bytes[0].is_ascii_alphabetic()) {
        return None;
    }
    if bytes.iter().all(|c| *c == b'_' || c.is_ascii_alphanumeric()) {
        Some(t)
    } else {
        None
    }
}

fn strip_outer_parentheses(mut text: &str) -> &str {
    loop {
        let t = text.trim();
        if !t.starts_with('(') || !t.ends_with(')') {
            return t;
        }
        let Some(close) = matching_delimiter(t, 0, '(', ')') else {
            return t;
        };
        if close != t.len() - 1 {
            return t;
        }
        text = &t[1..t.len() - 1];
    }
}

fn root_call(expression: &str) -> Option<(String, Vec<String>)> {
    let text = strip_outer_parentheses(expression.trim());
    let open = find_first_top_level_call_open(text)?;
    let close = matching_delimiter(text, open, '(', ')')?;
    if !text[close + 1..].trim().is_empty() {
        return None;
    }
    let raw_name = text[..open].trim();
    let name = if matches!(raw_name, "abi.encode" | "abi.encodePacked") {
        raw_name.to_string()
    } else {
        raw_name
            .rsplit('.')
            .next()
            .unwrap_or(raw_name)
            .trim()
            .to_string()
    };
    Some((name, split_top_level(&text[open + 1..close], ',')))
}

fn find_first_top_level_call_open(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut bracket = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'(' if bracket == 0 => return Some(i),
            b'"' | b'\'' => {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == quote && (i == 0 || bytes[i - 1] != b'\\') {
                        break;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_canonical_typed_hash_helper(name: &str) -> bool {
    matches!(
        name,
        "typedDataHash" | "toTypedDataHash" | "_hashTypedDataV4" | "_hashTypedData"
    )
}

fn canonical_typed_helper_arity(name: &str, len: usize) -> bool {
    match name {
        "typedDataHash" | "toTypedDataHash" => len == 2,
        "_hashTypedDataV4" | "_hashTypedData" => len == 1,
        _ => false,
    }
}

fn is_canonical_1901_prefix(expression: &str, model: &FunctionModel) -> bool {
    let resolved = resolve_simple_alias(expression, &model.assignments, 3);
    let c = compact(&resolved).to_ascii_lowercase();
    c.contains("\\x19\\x01")
        || c.contains("hex\"1901\"")
        || c == "0x1901"
        || c == "bytes2(0x1901)"
        || c == "bytes2(hex\"1901\")"
}

fn expression_role(expression: &str, model: &FunctionModel) -> TypedRole {
    let resolved = resolve_simple_alias(expression, &model.assignments, 4);
    let lower = compact(&resolved).to_ascii_lowercase();
    if lower.contains("domainseparator")
        || lower.contains("_domainseparator")
        || lower.contains("eip712domain")
        || lower.contains(".domain(")
        || lower.starts_with("domain(")
    {
        return TypedRole::Domain;
    }
    if lower.contains("structhash") {
        return TypedRole::Struct;
    }

    let definitions = parse_typehash_definitions(&model.contract_source);
    for (name, definition) in definitions {
        if !expression_depends_on(&resolved, &name) {
            continue;
        }
        if definition
            .declarations
            .first()
            .is_some_and(|x| x.name == "EIP712Domain")
        {
            return TypedRole::Domain;
        }
        return TypedRole::Struct;
    }
    TypedRole::Unknown
}

fn expression_double_hashes_role(expression: &str, model: &FunctionModel, role: TypedRole) -> bool {
    let resolved = resolve_simple_alias(expression, &model.assignments, 3);
    let Some((name, args)) = root_call(&resolved) else {
        return false;
    };
    if name != "keccak256" || args.len() != 1 {
        return false;
    }
    expression_role(&args[0], model) == role
}

fn resolve_function_name(
    caller: &FunctionModel,
    name: &str,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> Option<NodeID> {
    let mut same_file = caller
        .calls
        .iter()
        .filter(|call| call.name == name)
        .filter_map(|call| models.get(&call.callee).filter(|m| m.file == caller.file).map(|_| call.callee))
        .collect::<Vec<_>>();
    same_file.sort();
    same_file.dedup();
    if same_file.len() == 1 {
        return same_file.first().copied();
    }
    let mut global = caller
        .calls
        .iter()
        .filter(|call| call.name == name)
        .map(|call| call.callee)
        .collect::<Vec<_>>();
    global.sort();
    global.dedup();
    (global.len() == 1).then(|| global[0])
}

fn resolve_internal_call_by_name<'a>(
    caller: &'a FunctionModel,
    name: &str,
    models: &'a BTreeMap<NodeID, FunctionModel>,
) -> Option<&'a CallSite> {
    let matches = caller.calls.iter().filter(|c| c.name == name).collect::<Vec<_>>();
    if matches.len() == 1 && models.contains_key(&matches[0].callee) {
        Some(matches[0])
    } else {
        None
    }
}

fn first_return_expression(source: &str) -> Option<String> {
    let mut from = 0usize;
    while let Some(rel) = source[from..].find("return") {
        let pos = from + rel;
        let before_ok = pos == 0
            || !source.as_bytes().get(pos - 1).copied().is_some_and(|c| c == b'_' || c.is_ascii_alphanumeric());
        let end_word = pos + "return".len();
        let after_ok = end_word >= source.len()
            || !source.as_bytes().get(end_word).copied().is_some_and(|c| c == b'_' || c.is_ascii_alphanumeric());
        if before_ok && after_ok {
            let semi = source[end_word..].find(';')? + end_word;
            return Some(source[end_word..semi].trim().to_string());
        }
        from = end_word;
    }
    None
}

fn parse_typehash_definitions(source: &str) -> HashMap<String, TypeHashDefinition> {
    let mut out = HashMap::new();
    for statement in split_statements(source) {
        if !statement.contains("keccak256") || !statement.contains('"') || !statement.contains('=') {
            continue;
        }
        let Some(eq) = find_top_level_operator(&statement, "=") else {
            continue;
        };
        let Some(variable) = last_non_keyword_identifier(&statement[..eq]) else {
            continue;
        };
        let Some(encoded_type) = extract_keccak_string_literal(&statement[eq + 1..]) else {
            continue;
        };
        let declarations = parse_type_declarations(&encoded_type);
        if declarations.is_empty() {
            continue;
        }
        out.insert(
            variable.clone(),
            TypeHashDefinition {
                encoded_type,
                declarations,
            },
        );
    }
    out
}

fn extract_keccak_string_literal(text: &str) -> Option<String> {
    let k = text.find("keccak256")?;
    let open_rel = text[k..].find('(')?;
    let open = k + open_rel;
    let close = matching_delimiter(text, open, '(', ')')?;
    let inside = text[open + 1..close].trim();
    if !inside.starts_with('"') || !inside.ends_with('"') || inside.len() < 2 {
        return None;
    }
    Some(inside[1..inside.len() - 1].to_string())
}

fn parse_type_declarations(encoded: &str) -> Vec<TypeDecl> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < encoded.len() {
        let tail = &encoded[cursor..];
        let Some(open_rel) = tail.find('(') else {
            break;
        };
        let open = cursor + open_rel;
        let name = encoded[cursor..open].trim();
        if name.is_empty() || identifier_sequence(name).len() != 1 {
            break;
        }
        let Some(close) = matching_delimiter(encoded, open, '(', ')') else {
            break;
        };
        let fields = split_top_level(&encoded[open + 1..close], ',')
            .into_iter()
            .filter_map(|field| {
                let f = field.trim();
                let split = f.rfind(|c: char| c.is_whitespace())?;
                let ty = f[..split].trim();
                let name = f[split..].trim();
                if ty.is_empty() || name.is_empty() {
                    return None;
                }
                Some(TypeField {
                    ty: ty.to_string(),
                    name: name.to_string(),
                })
            })
            .collect();
        out.push(TypeDecl {
            name: name.to_string(),
            fields,
        });
        cursor = close + 1;
    }
    out
}

fn find_hash_encodings(source: &str) -> Vec<HashEncoding> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = source[from..].find("keccak256") {
        let k = from + rel;
        let Some(open_rel) = source[k..].find('(') else {
            break;
        };
        let open = k + open_rel;
        let Some(close) = matching_delimiter(source, open, '(', ')') else {
            from = open + 1;
            continue;
        };
        let inner = source[open + 1..close].trim();
        if let Some((name, args)) = root_call(inner) {
            if name == "abi.encode" || name == "abi.encodePacked" {
                out.push(HashEncoding {
                    packed: name == "abi.encodePacked",
                    args,
                });
            }
        }
        from = close.saturating_add(1);
        if from >= source.len() {
            break;
        }
    }
    out
}

fn expression_is_hashed_dynamic(
    expression: &str,
    function: &FunctionModel,
    models: Option<&BTreeMap<NodeID, FunctionModel>>,
) -> bool {
    let resolved = resolve_simple_alias(expression, &function.assignments, 4);
    if root_call(&resolved).is_some_and(|(name, _)| name == "keccak256") {
        return true;
    }
    let Some((name, _)) = root_call(&resolved) else {
        return false;
    };
    if !name.to_ascii_lowercase().contains("hash") {
        return false;
    }
    let Some(models) = models else {
        return true;
    };
    resolve_function_name(function, &name, models)
        .and_then(|id| models.get(&id))
        .is_some_and(|helper| helper.source.contains("keccak256"))
}

fn expression_is_eip712_array_hash(
    expression: &str,
    function: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    let resolved = resolve_simple_alias(expression, &function.assignments, 4);
    if let Some((name, args)) = root_call(&resolved) {
        if name == "keccak256" {
            // Hashing `abi.encode(array)` directly is not EIP-712 array encoding. Accept direct
            // hashing only when the hashed material is already an encoded/hash element sequence.
            if args.len() != 1 {
                return false;
            }
            let inner = compact(&args[0]);
            if inner.starts_with("abi.encode(") {
                return false;
            }
            if inner.starts_with("abi.encodePacked(") {
                let Some((_, packed_args)) = root_call(&args[0]) else {
                    return false;
                };
                if packed_args.len() == 1 {
                    if let Some(parameter) = function_parameter(function, &packed_args[0]) {
                        let base = base_type(&parameter.ty);
                        // For arrays of atomic/static values, abi.encodePacked(array) provides the
                        // concatenated 32-byte element encoding expected by EIP-712 before the outer
                        // keccak256. Arrays of dynamic values or structs require per-element hashes.
                        if is_dynamic_scalar_type(base) || is_custom_struct_type(base) {
                            return false;
                        }
                        return true;
                    }
                }
            }
            return true;
        }
        if name.to_ascii_lowercase().contains("hash") {
            return resolve_function_name(function, &name, models)
                .and_then(|id| models.get(&id))
                .is_some_and(|helper| {
                    helper.source.contains("keccak256")
                        && (helper.source.contains("for(")
                            || helper.source.contains("for (")
                            || helper.source.contains("abi.encodePacked"))
                });
        }
    }
    false
}

fn expression_is_struct_hash(
    expression: &str,
    function: &FunctionModel,
    models: &BTreeMap<NodeID, FunctionModel>,
) -> bool {
    let resolved = resolve_simple_alias(expression, &function.assignments, 4);
    if root_call(&resolved).is_some_and(|(name, _)| name == "keccak256") {
        return true;
    }
    if let Some((name, _)) = root_call(&resolved) {
        if name.to_ascii_lowercase().contains("hash") {
            return resolve_function_name(function, &name, models)
                .and_then(|id| models.get(&id))
                .is_some_and(|helper| helper.source.contains("keccak256"));
        }
    }
    false
}

fn referenced_custom_types(primary: &TypeDecl) -> Vec<String> {
    let mut out = primary
        .fields
        .iter()
        .map(|f| base_type(&f.ty))
        .filter(|ty| is_custom_struct_type(ty))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn is_dynamic_scalar_type(ty: &str) -> bool {
    matches!(compact(ty).as_str(), "string" | "bytes")
}

fn is_array_type(ty: &str) -> bool {
    compact(ty).contains('[')
}

fn base_type(ty: &str) -> &str {
    ty.split('[').next().unwrap_or(ty).trim()
}

fn is_custom_struct_type(ty: &str) -> bool {
    let base = base_type(ty);
    if matches!(base, "address" | "bool" | "string" | "bytes") {
        return false;
    }
    if base.starts_with("uint") || base.starts_with("int") {
        return false;
    }
    if base.starts_with("bytes") && base["bytes".len()..].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

fn normalize_solidity_type(ty: &str) -> String {
    let c = compact(ty);
    if c == "uint" {
        "uint256".into()
    } else if c == "int" {
        "int256".into()
    } else {
        c
    }
}

fn types_compatible(expected: &str, actual: &str) -> bool {
    normalize_solidity_type(expected) == normalize_solidity_type(actual)
}

fn expression_has_untrusted_root(expression: &str, model: &FunctionModel) -> bool {
    model.parameters.iter().any(|p| expression_depends_on(expression, &p.name))
        || expression.contains("msg.sender")
        || expression.contains("tx.origin")
}

fn looks_like_external_domain_provider(expression: &str) -> bool {
    let c = compact(expression);
    c.contains(".domainSeparator()") || c.contains(".DOMAIN_SEPARATOR()")
}

fn looks_like_numeric_literal(expression: &str) -> bool {
    let c = compact(expression).replace('_', "");
    if !c.is_empty() && c.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    if let Some((name, args)) = root_call(&c) {
        if (name.starts_with("uint") || name.starts_with("int")) && args.len() == 1 {
            let inner = compact(&args[0]).replace('_', "");
            return !inner.is_empty() && inner.chars().all(|ch| ch.is_ascii_digit());
        }
    }
    false
}

fn state_value_is_constructor_or_external_input(contract_source: &str, identifier: &str) -> bool {
    for (_, function, _, _) in parse_functions_from_source(contract_source) {
        if function.starts_with("constructor") || is_public_or_external(&function) {
            for statement in split_statements(&function) {
                let Some(eq) = find_top_level_operator(&statement, "=") else {
                    continue;
                };
                let lhs = &statement[..eq];
                if last_non_keyword_identifier(lhs).as_deref() == Some(identifier) {
                    return true;
                }
            }
        }
    }
    false
}

fn declaration_has_word(source: &str, identifier: &str, word: &str) -> bool {
    source.lines().any(|line| line.contains(identifier) && line.split_whitespace().any(|x| x == word))
}

fn is_persistent_lvalue(model: &FunctionModel, lhs: &str) -> bool {
    let ids = identifier_sequence(lhs);
    let Some(base) = ids.first() else {
        return false;
    };
    contract_level_declares_identifier(&model.contract_source, base)
}

fn contract_level_declares_identifier(source: &str, identifier: &str) -> bool {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        if let Some(q) = quote {
            if bytes[i] == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if bytes[i] == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match bytes[i] {
            b'"' | b'\'' => quote = Some(bytes[i]),
            b'{' => {
                depth += 1;
                if depth == 1 {
                    start = i + 1;
                }
            }
            b'}' => {
                depth -= 1;
                if depth < 1 {
                    start = i + 1;
                }
            }
            b';' if depth == 1 => {
                let statement = source[start..=i].trim();
                if !statement.contains("function")
                    && !statement.contains("constructor")
                    && identifiers_in_text(statement).contains(identifier)
                {
                    let ids = identifier_sequence(statement);
                    if ids.iter().any(|id| id == identifier) {
                        return true;
                    }
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn parse_write_facts(source: &str, after: usize) -> Vec<WriteFact> {
    let mut out = Vec::new();
    for (pos, statement) in split_statements_with_positions(source) {
        if pos <= after {
            continue;
        }
        let Some((op_pos, op_len)) = assignment_operator(&statement) else {
            continue;
        };
        let lhs = statement[..op_pos].trim();
        if lhs.starts_with("bytes32 ")
            || lhs.starts_with("uint")
            || lhs.starts_with("int")
            || lhs.starts_with("address ")
            || lhs.starts_with("bool ")
            || lhs.starts_with("bytes ")
            || lhs.starts_with("string ")
        {
            continue;
        }
        let rhs = statement[op_pos + op_len..].trim().trim_end_matches(';').trim();
        if lhs.is_empty() || rhs.is_empty() {
            continue;
        }
        out.push(WriteFact {
            lhs: lhs.to_string(),
            rhs: rhs.to_string(),
            pos,
        });
    }
    out
}

fn assignment_operator(statement: &str) -> Option<(usize, usize)> {
    for op in ["+=", "-=", "|=", "^=", "&=", "="] {
        let mut from = 0usize;
        while let Some(rel) = statement[from..].find(op) {
            let pos = from + rel;
            if op == "=" {
                let before = statement.as_bytes().get(pos.wrapping_sub(1)).copied();
                let after = statement.as_bytes().get(pos + 1).copied();
                if matches!(before, Some(b'!' | b'<' | b'>' | b'=')) || after == Some(b'=') {
                    from = pos + 1;
                    continue;
                }
            }
            return Some((pos, op.len()));
        }
    }
    None
}

fn split_statements_with_positions(source: &str) -> Vec<(usize, String)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut p = 0i32;
    let mut b = 0i32;
    let mut in_string = false;
    let mut quote = b'\0';
    let mut i = 0usize;
    while i < bytes.len() {
        let ch = bytes[i];
        if in_string {
            if ch == quote && (i == 0 || bytes[i - 1] != b'\\') {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match ch {
            b'"' | b'\'' => {
                in_string = true;
                quote = ch;
            }
            b'(' => p += 1,
            b')' => p -= 1,
            b'[' => b += 1,
            b']' => b -= 1,
            b';' if p == 0 && b == 0 => {
                let s = source[start..=i].trim();
                if !s.is_empty() {
                    out.push((start, s.to_string()));
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

fn unsigned_flows_to_external_call(source: &str, after: usize, unsigned: &BTreeSet<String>) -> bool {
    let tail = source.get(after..).unwrap_or("");
    for marker in [".call(", ".delegatecall(", ".staticcall(", ".call{"] {
        let mut from = 0usize;
        while let Some(rel) = tail[from..].find(marker) {
            let pos = from + rel;
            let receiver_start = tail[..pos]
                .rfind(|ch: char| matches!(ch, ';' | '{' | '}' | '\n'))
                .map(|x| x + 1)
                .unwrap_or(0);
            let receiver = tail[receiver_start..pos].trim();
            if !roots_from_set(receiver, unsigned).is_empty() {
                return true;
            }
            let call_open = pos + marker.find('(').unwrap_or(marker.len().saturating_sub(1));
            if tail.as_bytes().get(call_open).copied() == Some(b'(') {
                if let Some(close) = matching_delimiter(tail, call_open, '(', ')') {
                    if !roots_from_set(&tail[call_open + 1..close], unsigned).is_empty() {
                        return true;
                    }
                }
            }
            from = pos + marker.len();
        }
    }
    false
}

fn function_has_persistent_write(model: &FunctionModel) -> bool {
    let locals = collect_local_names(model);
    let parameters: BTreeSet<String> = model.parameters.iter().map(|p| p.name.clone()).collect();
    for (_, statement) in split_statements_with_positions(&model.source) {
        let Some((op, _)) = assignment_operator(&statement) else {
            continue;
        };
        let lhs = statement[..op].trim();
        if lhs.contains('[') {
            return true;
        }
        let Some(base) = first_non_keyword_identifier(lhs) else {
            continue;
        };
        if !locals.contains(&base) && !parameters.contains(&base) {
            return true;
        }
    }
    false
}

fn collect_local_names(model: &FunctionModel) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for statement in split_statements(&model.source) {
        let trimmed = statement.trim();
        if trimmed.starts_with("bytes32 ")
            || trimmed.starts_with("uint")
            || trimmed.starts_with("int")
            || trimmed.starts_with("address ")
            || trimmed.starts_with("bool ")
            || trimmed.starts_with("bytes ")
            || trimmed.starts_with("string ")
        {
            if let Some(eq) = find_top_level_operator(trimmed, "=") {
                if let Some(name) = last_non_keyword_identifier(&trimmed[..eq]) {
                    out.insert(name);
                }
            }
        }
    }
    out
}

fn functions_named(source: &str, target: &str) -> Vec<String> {
    parse_functions_from_source(source)
        .into_iter()
        .filter(|(name, _, _, _)| name == target)
        .map(|(_, source, _, _)| source)
        .collect()
}

fn parse_functions_from_source(source: &str) -> Vec<(String, String, usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while from < source.len() {
        let func = source[from..].find("function").map(|x| from + x);
        let ctor = source[from..].find("constructor").map(|x| from + x);
        let (pos, name) = match (func, ctor) {
            (Some(f), Some(c)) if c < f => (c, "constructor".to_string()),
            (Some(f), _) => {
                let after = f + "function".len();
                let raw = first_non_keyword_identifier(&source[after..]).unwrap_or_default();
                (f, raw)
            }
            (None, Some(c)) => (c, "constructor".to_string()),
            (None, None) => break,
        };
        let Some(open_rel) = source[pos..].find('{') else {
            break;
        };
        let open = pos + open_rel;
        let Some(close) = matching_delimiter(source, open, '{', '}') else {
            break;
        };
        out.push((name, source[pos..=close].to_string(), pos, close + 1));
        from = close + 1;
    }
    out
}

fn first_non_keyword_identifier(text: &str) -> Option<String> {
    identifier_sequence(text)
        .into_iter()
        .find(|x| !is_solidity_keyword(x))
}

fn last_non_keyword_identifier(text: &str) -> Option<String> {
    identifier_sequence(text)
        .into_iter()
        .rev()
        .find(|x| !is_solidity_keyword(x))
}

fn is_solidity_keyword(word: &str) -> bool {
    matches!(
        word,
        "address"
            | "bool"
            | "bytes"
            | "bytes32"
            | "calldata"
            | "constant"
            | "external"
            | "function"
            | "immutable"
            | "int"
            | "int256"
            | "internal"
            | "memory"
            | "payable"
            | "private"
            | "public"
            | "pure"
            | "returns"
            | "storage"
            | "string"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uint128"
            | "uint256"
            | "view"
    )
}

fn remove_word(text: &str, word: &str) -> String {
    text.split_whitespace().filter(|x| *x != word).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod eip712_implementation_tests {
    use super::*;

    #[test]
    fn parses_primary_and_referenced_types() {
        let ds = parse_type_declarations(
            "Action(address signer,Asset asset)Asset(address token,uint256 amount)",
        );
        assert_eq!(ds.len(), 2);
        assert_eq!(ds[0].name, "Action");
        assert_eq!(ds[0].fields.len(), 2);
        assert_eq!(ds[1].name, "Asset");
    }

    #[test]
    fn recognizes_canonical_prefix_spellings() {
        let model = FunctionModel {
            id: 1,
            source: String::new(),
            contract_source: String::new(),
            file: 0,
            entry_point: true,
            parameters: vec![],
            assignments: HashMap::new(),
            calls: vec![],
            direct_auth: AuthSummary::default(),
            signature_positions: vec![],
        };
        assert!(is_canonical_1901_prefix("\"\\x19\\x01\"", &model));
        assert!(is_canonical_1901_prefix("bytes2(0x1901)", &model));
        assert!(!is_canonical_1901_prefix("\"\\x19Ethereum Signed Message:\\n32\"", &model));
    }

    #[test]
    fn optional_domain_fields_are_not_implicitly_required() {
        let source = r#"
            bytes32 D = keccak256("EIP712Domain(string name,address verifyingContract)");
            function f() internal view returns(bytes32) {
                return keccak256(abi.encode(D, keccak256(bytes("App")), address(this)));
            }
        "#;
        let definitions = parse_typehash_definitions(source);
        assert!(definitions.values().any(|d| d.encoded_type.contains("verifyingContract")));
        assert!(definitions.values().all(|d| !d.encoded_type.contains("chainId")));
    }

    #[test]
    fn array_direct_abi_encode_is_not_eip712_array_encoding() {
        let model = FunctionModel {
            id: 1,
            source: "function f(address[] calldata xs) external {}".into(),
            contract_source: String::new(),
            file: 0,
            entry_point: true,
            parameters: parse_parameters("function f(address[] calldata xs) external {}"),
            assignments: HashMap::new(),
            calls: vec![],
            direct_auth: AuthSummary::default(),
            signature_positions: vec![],
        };
        assert!(!expression_is_eip712_array_hash(
            "keccak256(abi.encode(xs))",
            &model,
            &BTreeMap::new(),
        ));
    }

    #[test]
    fn typed_data_helper_is_canonical_only_at_root() {
        let model = FunctionModel {
            id: 1,
            source: String::new(),
            contract_source: "bytes32 X = keccak256(\"EIP712Domain(uint256 chainId)\");".into(),
            file: 0,
            entry_point: true,
            parameters: vec![],
            assignments: HashMap::new(),
            calls: vec![],
            direct_auth: AuthSummary::default(),
            signature_positions: vec![],
        };
        assert_eq!(
            classify_typed_digest("typedDataHash(domain, structHash)", &model, &BTreeMap::new(), 4),
            DigestStatus::Correct
        );
        assert_eq!(
            classify_typed_digest(
                "keccak256(abi.encodePacked(typedDataHash(domain, structHash), block.chainid))",
                &model,
                &BTreeMap::new(),
                4,
            ),
            DigestStatus::Incorrect
        );
    }

    #[test]
    fn wrong_domain_struct_order_is_rejected() {
        let mut assignments = HashMap::new();
        assignments.insert("d".into(), "domainSeparator".into());
        assignments.insert("h".into(), "structHash".into());
        let model = FunctionModel {
            id: 1,
            source: String::new(),
            contract_source: String::new(),
            file: 0,
            entry_point: true,
            parameters: vec![],
            assignments,
            calls: vec![],
            direct_auth: AuthSummary::default(),
            signature_positions: vec![],
        };
        assert_eq!(
            classify_typed_digest(
                "keccak256(abi.encodePacked(\"\\x19\\x01\", h, d))",
                &model,
                &BTreeMap::new(),
                4,
            ),
            DigestStatus::Incorrect
        );
    }

    fn run(path: &str) -> usize {
        let context = crate::detect::test_utils::load_solidity_source_unit(path);
        let mut detector = EIP712ImplementationDetector::default();
        detector.detect(&context).unwrap();
        detector.instances().len()
    }

    #[test]
    fn accepts_correct_typed_data() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/CorrectTypedData.sol"),
            0
        );
    }

    #[test]
    fn detects_missing_prefix() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/MissingPrefix.sol"),
            1
        );
    }

    #[test]
    fn detects_wrong_struct_encoding() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/WrongStructEncoding.sol"),
            1
        );
    }

    #[test]
    fn accepts_optional_domain_fields() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/OptionalDomainSafe.sol"),
            0
        );
    }

    #[test]
    fn detects_caller_supplied_domain() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/CallerSuppliedDomain.sol"),
            1
        );
    }

    #[test]
    fn detects_unsigned_runtime_target() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/UnsignedTarget.sol"),
            1
        );
    }

    #[test]
    fn accepts_signed_runtime_target() {
        assert_eq!(
            run("../tests/contract-playground/src/eip712-implementation/SignedTarget.sol"),
            0
        );
    }
}
