// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_AirdropAdversarialSafe10 {
    address public immutable authorizedSigner;
    mapping(bytes32=>bool) public usedDigest;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalAuthorized;
    constructor(address signer_) { authorizedSigner = signer_; }

    function claimBySig(address actor,address recipient,uint256 amount,bytes32 actionId,bytes calldata signature) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        bytes32 signatureHash=keccak256(signature); require(signatureHash!=bytes32(0),"empty telemetry"); require(!usedDigest[digest],"used"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); usedDigest[digest]=true;
        allowance[actor][recipient] = amount;
        unchecked { totalAuthorized += amount; }
    }
}
