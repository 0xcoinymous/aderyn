// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongReturnTypeUint256028 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    function isValidSignature(bytes32 hash, bytes calldata signature) external pure returns (uint256) {
        hash; signature;
        return uint256(uint32(MAGIC));
    }
}
