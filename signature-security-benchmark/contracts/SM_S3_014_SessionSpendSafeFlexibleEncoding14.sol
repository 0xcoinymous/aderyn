// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SessionSpendSafeFlexibleEncoding14 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    constructor(address signer_) { authorizedSigner = signer_; }

    function spendBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        (bytes32 r,bytes32 s,uint8 v)=SM_MalleabilityBenchLib.splitFlexible(signature); require(!usedAuthorization[actionId],"used"); require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); usedAuthorization[actionId]=true;
        cumulative[actionId] += amount;
        participant[actor] = true;
    }
}
