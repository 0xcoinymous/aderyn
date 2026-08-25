// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongFunctionShape4034 {
    function isValidSignature(uint256 hash, bytes calldata signature) external pure returns (bytes4) {
        hash; signature;
        return 0x1626ba7e;
    }
}
