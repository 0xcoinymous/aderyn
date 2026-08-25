// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_AttackerControlledIdentityBranchWrapper024 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    constructor(address owner_) { owner = owner_; }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        if (signature.length < 20) return FAIL;
        address identity;
        assembly { identity := shr(96, calldataload(signature.offset)) }
        (bool success, bytes memory ret) = identity.staticcall(abi.encodeWithSignature("isAuthorized(bytes32)", hash));
        return success && ret.length >= 32 && abi.decode(ret, (bool)) ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        bytes4 value = _core(hash, signature);
        if (value == MAGIC) return MAGIC;
        return FAIL;
    }
}
