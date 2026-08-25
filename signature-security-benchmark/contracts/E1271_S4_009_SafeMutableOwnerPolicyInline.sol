// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeMutableOwnerPolicyInline009 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public owner;
    constructor(address owner_) { require(owner_ != address(0), "owner"); owner = owner_; }
    function setOwner(address owner_) external { require(msg.sender == owner, "owner"); require(owner_ != address(0), "zero"); owner = owner_; }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        return recovered == owner ? MAGIC : FAIL;
    }
}
