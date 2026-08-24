// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RoyaltyClaimRawSignatureKey26 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(bytes32 => uint256) public totals;

    uint256 public operationCount;
        bytes32 public operationTag;
    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRoyalty(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(abi.encode(signature));
        require(!consumedSignature[key], "signature used");
        require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        totals[actionId] = totals[actionId] + amount;
        operationCount += 1;
                operationTag = keccak256(abi.encode(actionId, amount));
    }
}
