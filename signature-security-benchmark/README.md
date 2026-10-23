# Signature Security Benchmark

Solidity contracts for evaluating detectors of signature-related vulnerabilities.
All contracts live in one folder, `contracts/`. It holds two kinds of files.

## 1. Synthetic cases (1,096)

The ground-truth label of each synthetic case is encoded in its filename.

```
<FAMILY>_<GROUP>_<NNN>_<Name>.sol
```

| Part | Meaning |
|---|---|
| `FAMILY` | Vulnerability family / target detector (see below) |
| `GROUP` | `V1`..`V4` = **vulnerable**, vulnerability class 1..4 of the family; `S1`..`S5` = **safe** variant; `A` = **adversarial safe** (looks suspicious but is safe) |
| `NNN` | Case number within the family |

Each family also has one shared helper library (`*BenchLib.sol`) that is not a test case.
All synthetic cases compile with solc 0.8.29.

| Family | Detector | Cases |
|---|---|---|
| `SR` | `SignatureReplayDetector` | 204 |
| `SM` | `SignatureMalleabilityDetector` | 204 |
| `NM` | `NonceManagementDetector` | 128 |
| `E712` | `EIP712ImplementationDetector` | 128 |
| `E1271` | `EIP1271VerificationDetector` | 216 |
| `SF` | `SignatureFreshnessDetector` | 216 |
| | **Total** | **1096** |

## 2. Real-world cases (18 files, 19 cases)

Real contracts, each flattened into one self-contained file (all imports inlined with `forge flatten`)
and named `<Project>_<OriginalFile>.sol`. They keep their original compiler versions (0.4.24 to 0.8.x).
The first lines of each file name the case and its source repository.

- **Vulnerable (8 cases, 7 files):** audit-confirmed weaknesses (SWC-117, SWC-121, SWC-122) from the
  DAppSCAN dataset: `UMA_SpokePool` (2 cases), `zNS_StakingController`, `ElementFinance_ERC20Permit`,
  `AZTEC_ZkAssetBase`, `Dharma_DharmaKeyRegistryV1`, `Umbra_Umbra`, `ZeroEx_MixinSignatureValidator`.
- **Clean (11 files):** widely used signature code without known findings of these classes:
  `OZ_ERC20Permit`, `OZ_ERC20Votes`, `OZ_MinimalForwarder`, `UniswapV2_UniswapV2ERC20`,
  `Permit2_SignatureTransfer`, `Permit2_AllowanceTransfer`, `MakerDAO_Dai`, `Compound_Comp`,
  `Uniswap_Uni`, `Safe_GnosisSafe`, `Circle_EIP3009`.

Labels, target contract and function, audit source and compiler version of each real-world case are
kept outside this folder, in the evaluation repository (`eval/realworld/cases.json`).
