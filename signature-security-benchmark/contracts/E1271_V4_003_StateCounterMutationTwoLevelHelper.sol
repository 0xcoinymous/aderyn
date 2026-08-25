// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_StateCounterMutationTwoLevelHelper003 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    uint256 public validationCount;
    constructor(address owner_) { owner = owner_; }

    function _leaf(bytes32 hash, bytes calldata signature) private returns (bytes4) {
        validationCount += 1;
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        return recovered == owner ? MAGIC : FAIL;
    }

    function _core(bytes32 hash, bytes calldata signature) internal returns (bytes4) {
        return _leaf(hash, signature);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
        return _core(hash, signature);
    }
}
