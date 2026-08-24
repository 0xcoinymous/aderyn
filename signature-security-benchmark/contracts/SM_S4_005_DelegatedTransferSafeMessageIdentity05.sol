// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_DelegatedTransferSafeMessageIdentity05 {
    address public immutable authorizedSigner;
    mapping(bytes32=>bool) public usedDigest;
    bytes32 public lastSignatureTelemetry;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;

    constructor(address signer_) { authorizedSigner = signer_; }

    function delegatedTransfer(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(!usedDigest[digest],"used"); require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); lastSignatureTelemetry=keccak256(abi.encode(r,s,v)); usedDigest[digest]=true;
        completed[actionId] = true;
        completionCount += 1;
    }
}
