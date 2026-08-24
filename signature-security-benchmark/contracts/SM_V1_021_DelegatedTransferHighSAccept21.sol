// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SM_V1_021_Verifier {
    function verify(bytes32 digest, address signer, uint8 v, bytes32 r, bytes32 s) external pure returns (bool) {
        return ecrecover(digest, v, r, s) == signer;
    }
}

contract SM_DelegatedTransferHighSAccept21 {
    address public immutable authorizedSigner;
    SM_SM_V1_021_Verifier public immutable verifier;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;
    mapping(address => bool) public touchedActor;
    constructor(address signer_, SM_SM_V1_021_Verifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }
    function delegatedTransfer(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(verifier.verify(digest, authorizedSigner, v, r, s), "invalid signature");
        executedAt[actionId] = block.number;
        calls += 1;
        touchedActor[actor] = true;
    }
}
