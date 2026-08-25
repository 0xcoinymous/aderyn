// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeReadOnlyRevocationInline013 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    mapping(bytes32 => bool) public revoked;
    constructor(address owner_) { owner = owner_; }

    function setRevoked(bytes32 h, bool v) external { require(msg.sender == owner, "owner"); revoked[h] = v; }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (revoked[hash]) return FAIL;
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        return recovered == owner ? MAGIC : FAIL;
    }
}
