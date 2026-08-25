// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongFunctionShape2032 {
    function isValidSignature(bytes32 hash, bytes32 signature) external pure returns (bytes4) {
        hash; signature;
        return 0x1626ba7e;
    }
}
