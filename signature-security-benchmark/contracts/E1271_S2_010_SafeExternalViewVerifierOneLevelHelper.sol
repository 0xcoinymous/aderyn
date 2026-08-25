// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeExternalViewVerifierOneLevelHelper010 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    E1271_IReadOnlyVerifier public immutable verifier;
    constructor(address owner_, E1271_IReadOnlyVerifier verifier_) { owner = owner_; verifier = verifier_; }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        bool ok = verifier.verify(owner, hash, signature);
        return ok ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
