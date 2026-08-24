// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_AdminGrantSafeFlexibleEncoding09 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;

    constructor(address signer_) { authorizedSigner = signer_; }

    function grantBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(!usedAuthorization[digest],"used"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); usedAuthorization[digest]=true;
        completed[actionId] = true;
        completionCount += 1;
    }
}
