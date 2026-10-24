# Signature Security Benchmark

Real Solidity contracts for evaluating detectors of signature-related vulnerabilities.
All contracts live in one folder, `contracts/`. Every file is the verified source of a deployed
contract, so no file name carries its label; labels and provenance are kept in the evaluation
repository (`eval/datasets/labels.csv`, `eval/datasets/sources.csv`, `eval/realworld/cases.json`).

## 1. Labelled datasets from published studies (1,056 files)

Files are named `<address>_<ContractName>.sol` (lower-case address, official contract name).

| Dataset | Source | Contracts | Labels |
|---|---|---|---|
| D1 | LASiR (ICSE 2026), `Dataset/RQ2/Labeled_Data.csv`: random sample of the Ethereum contracts that use `ecrecover` | 470 distinct (the published 500 rows list 30 contracts twice) | signature replay, 71 positive / 399 negative |
| D2 | CryptoScan (TSE 2025), `Experiments/Dataset2`: random sample of crypto-related Ethereum contracts | 92 (of 96; 3 sources missing from the artifact) | every signature defect type annotated |
| D3 | CryptoScan, `Experiments/Dataset1`: contracts CryptoScan reported for six signature defect types | 504 | manual TP/FP per type |

D1 sources are taken from the tintinweb smart-contract-sanctuary mirror at the commit the LASiR
artifact lists, D2 and D3 sources from `Dataset/SourceCode` of the CryptoScan repository (commit
`257913106fde`). Nine D1 contracts also appear in D2 or D3, and one contract is in both D2 and D3.
`eval/datasets/fetch.py labelled` rebuilds this part of the folder.

## 2. Audited and widely used contracts (18 files, 19 cases)

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

## 3. Large unlabelled dataset (not stored here)

LASiR DB1: the 15,383 contracts on Ethereum, BSC, Polygon and Arbitrum that call `ecrecover`, used
for prevalence and runtime only. The address lists are in `eval/datasets/raw/lasir/DB1_*.csv`;
`eval/datasets/fetch.py large --out <dir>` downloads the sources (about 0.5 GB).
