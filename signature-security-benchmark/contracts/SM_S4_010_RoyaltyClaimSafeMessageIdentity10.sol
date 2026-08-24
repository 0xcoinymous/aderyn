// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RoyaltyClaimSafeMessageIdentity10 {
    address public immutable authorizedSigner;
    mapping(bytes32=>bool) public usedAuthorization;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    bytes32 public lastAction;
    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRoyalty(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(!usedAuthorization[actionId],"used"); require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); usedAuthorization[actionId]=true;
        cumulative[actionId] += amount;
        participant[actor] = true;
        lastAction = actionId;
    }
}
