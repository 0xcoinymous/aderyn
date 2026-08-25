// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_ExternalStateChangingCallBranchWrapper024 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    address public immutable mutator;
    constructor(address owner_, address mutator_) { owner = owner_; mutator = mutator_; }

    function validate(bytes32 hash, bytes calldata signature) public returns (bytes4) {
        (bool touched, ) = mutator.call(abi.encodeWithSelector(E1271_IMutator.touch.selector, hash));
        if (!touched) return FAIL;
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        return recovered == owner ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
        return validate(hash, signature);
    }
}
