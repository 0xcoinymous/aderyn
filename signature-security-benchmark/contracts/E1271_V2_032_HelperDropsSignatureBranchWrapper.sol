// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_HelperDropsSignatureBranchWrapper032 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    mapping(bytes32 => bool) public approvedHash;
    constructor(address owner_) { owner = owner_; }

    function setApprovedHash(bytes32 h, bool v) external { require(msg.sender == owner, "owner"); approvedHash[h] = v; }
    function _validHashOnly(bytes32 hash) internal view returns (bool) { return approvedHash[hash]; }

    function validate(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        signature;
        return _validHashOnly(hash) ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return validate(hash, signature);
    }
}
