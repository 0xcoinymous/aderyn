// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_OracleUpdateAdversarialSafe08 {
    address public immutable authorizedSigner;
    mapping(bytes32=>uint256) public messageExecutions;
    mapping(bytes32 => uint256) public totals;

    constructor(address signer_) { authorizedSigner = signer_; }

    function updateBySig(address actor,address recipient,uint256 amount,bytes32 actionId,bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(messageExecutions[digest]==0,"used"); address recovered=SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature); if(recovered!=authorizedSigner) revert("invalid"); messageExecutions[digest]=1;
        totals[actionId] = totals[actionId] + amount;
    }
}
