// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BatchPaymentSafeLibraryCanonical11 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public credited;

    constructor(address signer_) { authorizedSigner = signer_; }

    function batchPayBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        address recovered=SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s); if(recovered!=authorizedSigner) revert("invalid");
        credited[recipient] += amount;
    }
}
