// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeHashPolicyAndSignatureTwoLevelHelper007 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    mapping(bytes32 => bool) public allowedHash;
    constructor(address owner_) { owner = owner_; }

    function setAllowedHash(bytes32 h, bool v) external { require(msg.sender == owner, "owner"); allowedHash[h] = v; }

    function _leaf(bytes32 hash, bytes calldata signature) private view returns (bytes4) {
        if (!allowedHash[hash]) return FAIL;
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        return recovered == owner ? MAGIC : FAIL;
    }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        return _leaf(hash, signature);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
