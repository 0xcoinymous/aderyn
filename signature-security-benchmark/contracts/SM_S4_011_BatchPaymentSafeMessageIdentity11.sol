// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BatchPaymentSafeMessageIdentity11 {
    address public immutable authorizedSigner;
    mapping(address=>uint256) public nonces;
    mapping(address => uint256) public credited;

    mapping(address => uint256) public actorUses;
    constructor(address signer_) { authorizedSigner = signer_; }

    function batchPayBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce=nonces[actor]; bytes32 digest=keccak256(abi.encode(actor,recipient,amount,actionId,nonce,address(this)));
        require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); nonces[actor]=nonce+1;
        credited[recipient] += amount;
        actorUses[actor] += 1;
    }
}
