# signature-security-benchmark

Unified Solidity benchmark for evaluating signature-security detectors added to Aderyn v0.6.8.

## Current families

- `SR_` — SignatureReplayDetector: 204 labeled target contracts.
- `SM_` — SignatureMalleabilityDetector: 204 labeled target contracts.

All target Solidity files coexist in `contracts/`. Two support sources (`SR_ReplayBenchLib.sol` and `SM_MalleabilityBenchLib.sol`) are compiled and scanned but are **not scored as target cases**.

Current total: **408 labeled target contracts** and **410 Solidity files including support sources**.

## SignatureMalleabilityDetector ground truth

- 120 vulnerable cases:
  - 30 high-s/non-canonical-s acceptance (`SM_V1_`).
  - 30 permissive/incorrect `v` handling (`SM_V2_`).
  - 30 multiple accepted serialization/representation forms (`SM_V3_`).
  - 30 raw-signature-derived uniqueness/replay keys (`SM_V4_`).
- 84 safe cases:
  - 20 canonical raw-ecrecover controls (`SM_S1_`).
  - 20 canonical library-recovery controls (`SM_S2_`).
  - 20 safe flexible ERC-2098/traditional representation controls (`SM_S3_`).
  - 12 safe message-based uniqueness controls (`SM_S4_`).
  - 12 adversarial safe controls (`SM_A_`).

## Run Aderyn

From the Aderyn repository root:

```bash
cargo run -- ./signature-security-benchmark
```

Aderyn's stock low-severity `ecrecover` finding is **not** equivalent to a `SignatureMalleabilityDetector` classification. The benchmark deliberately includes safe raw-ecrecover cases with correct low-s/v checks and vulnerable helper-based cases where the target does not directly contain an `ecrecover` identifier.

## Evaluation

For a detector family, score only cases whose `label_scope` identifies that detector (or cases independently cross-labeled for it). Do not treat unlabeled families as automatic true negatives.

- TP: vulnerable case flagged by the detector.
- FN: vulnerable case not flagged.
- FP: safe case flagged.
- TN: safe case not flagged.
- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN).
- F1 = 2 * Precision * Recall / (Precision + Recall).

Multiple findings in one target contract still count as one positive classification when calculating contract-level confusion matrices.

## Primary and secondary labels

`primary_detector` identifies the benchmark family intentionally tested by the case. `secondary_detectors` is populated only when another vulnerability is explicitly present by design. It is not a substitute for an independently validated per-detector ground-truth label.

## Future merge rules

Reserve prefixes: `SR_`, `SM_`, `NM_`, `E712_`, `E1271_`, `SF_`. New families must preserve the 21-column unified manifest schema, use globally unique case/file/declaration names, and place target Solidity sources directly under `contracts/`.
