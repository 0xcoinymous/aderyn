// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_UnsafeEOAFallbackInline011 {
    uint256 public accepted;
    bytes32 public lastHash;

    function _check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length == 0) return true;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
        require(_check(signer, hash, signature), "invalid");
        accepted += 1;
        lastHash = hash;
        return true;
    }
}
