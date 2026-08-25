// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_TrustedCallerOnlyBranchWrapper020 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    address public immutable trustedCaller;
    constructor(address owner_, address caller_) { owner = owner_; trustedCaller = caller_; }

    function validate(bytes32 hash, bytes calldata signature) public view returns (bytes4) {
        hash; signature;
        return msg.sender == trustedCaller ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return validate(hash, signature);
    }
}
