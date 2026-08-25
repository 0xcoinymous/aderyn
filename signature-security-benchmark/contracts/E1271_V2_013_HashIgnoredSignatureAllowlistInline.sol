// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_HashIgnoredSignatureAllowlistInline013 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    mapping(bytes32 => bool) public approvedSignature;
    constructor(address owner_) { owner = owner_; }

    function setApprovedSignature(bytes32 h, bool v) external { require(msg.sender == owner, "owner"); approvedSignature[h] = v; }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        hash;
        return approvedSignature[keccak256(signature)] ? MAGIC : FAIL;
    }
}
