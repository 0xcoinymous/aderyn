// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RoyaltyClaimHighSAccept26 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;

    uint256 public operationCount;
        bytes32 public operationTag;
    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRoyalty(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(SM_MalleabilityBenchLib.recoverRaw(digest, v, r, s) == authorizedSigner, "invalid signature");
        completed[actionId] = true;
        completionCount += 1;
        operationCount += 1;
                operationTag = keccak256(abi.encode(actionId, amount));
    }
}
