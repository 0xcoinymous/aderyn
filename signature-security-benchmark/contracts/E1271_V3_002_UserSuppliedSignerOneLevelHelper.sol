// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_UserSuppliedSignerOneLevelHelper002 {
    uint256 public accepted;
    bytes32 public lastHash;

    function _inner(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        bytes4 result = E1271_IERC1271(signer).isValidSignature(hash, signature);
        return result == 0x1626ba7e;
    }

    function _check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        return _inner(signer, hash, signature);
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = _check(signer, hash, signature);
        if (!ok) revert("invalid");
        lastHash = hash;
        accepted = accepted + 1;
        return ok;
    }
}
