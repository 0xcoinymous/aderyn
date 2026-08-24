# Research Sources

This benchmark uses independently written minimal fixtures. Historical/CVE-inspired cases are semantic reproductions, not verbatim copies of vulnerable production contracts.

## Signature malleability foundations

- EIP-2, Homestead Hard-fork Changes: transaction-level high-s rejection while the `ecrecover` precompile remains permissive. https://eips.ethereum.org/EIPS/eip-2
- ERC-2098, Compact Signature Representation: 64-byte compact representation using the top bit of `s` for y parity. https://eips.ethereum.org/EIPS/eip-2098
- OpenZeppelin ECDSA documentation: canonical recovery rejects high-s and requires v=27/28; developers should not use signatures as unique identifiers. https://docs.openzeppelin.com/contracts/5.x/api/utils/cryptography

## Public vulnerability/advisory cases

- CVE-2022-35961 / GHSA-4h98-2769-gh6h: OpenZeppelin Contracts >=4.1.0,<4.7.3 `ECDSA.recover(bytes32,bytes)` and `tryRecover(bytes32,bytes)` accepted compact and traditional encodings; security impact arises when raw signature representation itself is used for reuse/replay protection. https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h
- NVD CVE-2022-35961 entry. https://nvd.nist.gov/vuln/detail/CVE-2022-35961
- OpenZeppelin v4.7.3 changelog: bytes overloads stopped accepting compact signatures to prevent this malleability class. https://docs.openzeppelin.com/contracts/5.x/changelog
- TCH token exploit (May 2024, BNB Chain): `keccak256(signature)` used as replay identity while `if (v < 27) v += 27` allowed alternate serialized v values recovering the same signer; public reproduction reports roughly 18.6k BUSDT loss. https://crypto.training/hacks/2024-05-tch/

## Labeling policy

- `historically-inspired`: independently written fixture based on a confirmed public exploit pattern.
- `cve-inspired`: independently written fixture based on a public CVE/security advisory.
- `standards-inspired`: safe or edge-case fixture derived from standard/library rules.
- `synthetic`: independently designed static-analysis test case.
