# Validation Report

## Scope

This revision contains two detector families in one flat `contracts/` directory:

- `SR_`: 204 labeled SignatureReplayDetector target contracts.
- `SM_`: 204 labeled SignatureMalleabilityDetector target contracts.
- Support sources: `SR_ReplayBenchLib.sol` and `SM_MalleabilityBenchLib.sol`.

Total: **408 labeled target contracts** and **410 Solidity source files**.

## SignatureMalleabilityDetector ground truth

- Vulnerable: **120**
  - 30 high-s/non-canonical-s acceptance.
  - 30 permissive/incorrect v handling.
  - 30 multiple accepted signature representations/serialization forms.
  - 30 raw-signature-derived uniqueness/replay keys.
- Safe: **84**
  - 20 canonical raw-ecrecover controls.
  - 20 canonical library-recovery controls.
  - 20 safe compact/traditional representation controls.
  - 12 safe message-based uniqueness controls.
  - 12 adversarial safe controls.

## Automated structural validation performed

`python tools/validate_corpus.py` passes and verifies:

- exact 21-column unified manifest schema;
- 408 unique case IDs;
- 408 unique target filenames;
- 408 unique target contract names;
- 424 unique top-level Solidity declarations;
- 408 unique semantic fingerprints;
- exact CSV/JSON case and ordering agreement;
- all manifest-referenced Solidity target files exist;
- all local imports resolve in the flat `contracts/` directory;
- all Solidity files use exact `pragma solidity 0.8.29;`;
- all top-level declarations use a reserved `SR_` or `SM_` prefix;
- no duplicate function parameter identifiers detected;
- balanced parentheses/braces/brackets after stripping comments and string bodies;
- SignatureMalleabilityDetector label counts are exactly 120 vulnerable / 84 safe;
- all **204 SM targets remain unique under aggressive structural normalization that erases user-selected identifiers, string literals, and numeric/hex constants**. This check is intended to reject rename-only or constant-only corpus inflation.

## Stock-Aderyn discrimination design

Among the 204 SM target contracts:

- 102 vulnerable target files contain a direct `ecrecover` expression and 18 vulnerable targets hide recovery behind a helper/library/abstraction.
- 23 safe target files contain direct `ecrecover`, while 61 safe targets use helper/library/representation abstractions.

This intentionally prevents the stock Aderyn `ecrecover` warning from serving as a reliable malleability classifier: raw `ecrecover` appears in both safe and vulnerable ground truth, while some vulnerable targets do not directly expose the primitive.

## Compiler validation status

A Solidity compiler is not installed in this execution environment, so an actual `solc 0.8.29` compiler pass could not be executed here. The corpus includes `tools/compile_with_solc.sh` and `foundry.toml` for an authoritative compile on the user's Aderyn/Foundry environment.

Run from the dataset root:

```bash
./tools/compile_with_solc.sh
```

or from the Aderyn repository root:

```bash
cargo run -- ./signature-security-benchmark
```

Do not treat structural validation as a substitute for the real compiler pass. Any compiler error found by the user's environment should be corrected before baseline metrics are recorded.
