// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_TreasuryPaymentRawSignatureKey19 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;

    mapping(address => uint256) public actorUses;
    constructor(address signer_) { authorizedSigner = signer_; }

    function payBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(abi.encodePacked(signature));
        require(!consumedSignature[key], "signature used");
        require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        completed[actionId] = true;
        completionCount += 1;
        actorUses[actor] += 1;
    }
}
