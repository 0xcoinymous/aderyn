// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_UnsafeOwnerFallbackTwoLevelHelper033 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public owner;
    constructor(address owner_) { owner = owner_; }
    function clearOwner() external { owner = address(0); }

    function _leaf(bytes32 hash, bytes calldata signature) private view returns (bytes4) {
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        if (owner == address(0)) return recovered != address(0) ? MAGIC : FAIL;
        return recovered == owner ? MAGIC : FAIL;
    }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        return _leaf(hash, signature);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
