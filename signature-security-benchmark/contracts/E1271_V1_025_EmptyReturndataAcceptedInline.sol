// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_EmptyReturndataAcceptedInline025 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function _check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        if (!success) return false;
        if (ret.length == 0) return true;
        return bytes4(ret) == 0x1626ba7e;
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        require(_check(authorizedSigner, hash, signature), "invalid");
        accepted += 1;
        lastHash = hash;
        return true;
    }
}
