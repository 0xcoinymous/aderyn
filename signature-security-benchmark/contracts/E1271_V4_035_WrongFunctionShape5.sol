// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongFunctionShape5035 {
    function isValidSignature(bytes32 hash) external pure returns (bytes4) {
        hash;
        return 0x1626ba7e;
    }
}
