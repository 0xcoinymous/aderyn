// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeSignatureCheckerInline013 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function _check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        return E1271_BenchChecker.isValidNow(signer, hash, signature);
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        require(_check(authorizedSigner, hash, signature), "invalid");
        accepted += 1;
        lastHash = hash;
        return true;
    }
}
