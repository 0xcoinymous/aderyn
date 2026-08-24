# Ground-Truth Schema

The unified manifests preserve these 21 columns exactly:

`case_id, filename, contract_name, detector_family, primary_detector, secondary_detectors, label_scope, label, vulnerability_class, subproblem, application_context, verification_mechanism, protection_mechanism, control_flow_shape, rationale, expected_stock_aderyn_0_6_8, expected_custom_detector, source_class, research_basis, semantic_fingerprint, original_case_id`

`label` is the vulnerable/safe ground truth for the detector named by `label_scope`. An empty `secondary_detectors` value means no additional detector label has been asserted. A secondary detector name records an intentionally present cross-category issue, but it should not be scored as a formal label until independently reviewed for that detector.
