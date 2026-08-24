// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RefundSafeMessageIdentity12 {
    address public immutable authorizedSigner;
    mapping(bytes32=>uint256) public consumedAt;
    mapping(bytes32 => uint256) public totals;

    mapping(bytes32 => uint256) public actionUses;
    constructor(address signer_) { authorizedSigner = signer_; }

    function refundBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        bytes32 messageKey=keccak256(abi.encode(digest,actor)); require(consumedAt[messageKey]==0,"used"); require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); consumedAt[messageKey]=block.number;
        totals[actionId] = totals[actionId] + amount;
        actionUses[actionId] = block.number;
    }
}
