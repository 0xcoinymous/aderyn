// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_PermitLikeAdversarialSafe06 {
    address public immutable authorizedSigner;
    mapping(bytes32=>bool) public blockedDigest;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    constructor(address signer_) { authorizedSigner = signer_; }

    function permit(address actor,address recipient,uint256 amount,bytes32 actionId,bytes calldata signature) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(!blockedDigest[digest],"blocked"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid");
        cumulative[actionId] += amount;
        participant[actor] = true;
    }
}
