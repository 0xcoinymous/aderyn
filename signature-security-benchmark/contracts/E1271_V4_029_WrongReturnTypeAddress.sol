// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongReturnTypeAddress029 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    function isValidSignature(bytes32 hash, bytes calldata signature) external pure returns (address) {
        hash; signature;
        return address(uint160(uint32(MAGIC)));
    }
}
