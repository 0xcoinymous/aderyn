# Signature Security Benchmark

Synthetic Solidity contracts for evaluating detectors of signature-related vulnerabilities.
All contracts live in `contracts/`. The ground-truth label of each case is encoded in its filename.

## Filename convention

```
<FAMILY>_<GROUP>_<NNN>_<Name>.sol
```

| Part | Meaning |
|---|---|
| `FAMILY` | Vulnerability family / target detector (see below) |
| `GROUP` | `V1`..`V4` = **vulnerable**, vulnerability class 1..4 of the family; `S1`..`S5` = **safe** variant; `A` = **adversarial safe** (looks suspicious but is safe) |
| `NNN` | Case number within the family |

Each family also has one shared helper library (`*BenchLib.sol`) that is not a test case.

| Family | Detector | Cases |
|---|---|---|
| `SR` | `SignatureReplayDetector` | 204 |
| `SM` | `SignatureMalleabilityDetector` | 204 |
| `NM` | `NonceManagementDetector` | 128 |
| `E712` | `EIP712ImplementationDetector` | 128 |
| `E1271` | `EIP1271VerificationDetector` | 216 |
| `SF` | `SignatureFreshnessDetector` | 216 |
| | **Total** | **1096** |
