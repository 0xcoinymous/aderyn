// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongFunctionShape3033 {
    function isValidSignature(bytes32 hash, bytes calldata signature, uint256 mode) external pure returns (bytes4) {
        hash; signature; mode;
        return 0x1626ba7e;
    }
}
