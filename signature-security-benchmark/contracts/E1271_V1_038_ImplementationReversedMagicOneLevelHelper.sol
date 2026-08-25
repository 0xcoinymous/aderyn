// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_ImplementationReversedMagicOneLevelHelper038 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    constructor(address owner_) { owner = owner_; }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        if (recovered == owner) return FAIL;
        if (recovered == address(0)) return MAGIC;
        return MAGIC;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
