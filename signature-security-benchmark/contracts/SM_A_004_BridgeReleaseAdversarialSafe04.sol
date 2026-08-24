// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BridgeReleaseAdversarialSafe04 {
    address public immutable authorizedSigner;
    mapping(address=>uint256) public nonces;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBySig(address actor,address recipient,uint256 amount,bytes32 actionId,bytes calldata signature) external {
        uint256 nonce=nonces[actor]; bytes32 digest=keccak256(abi.encode(actor,recipient,amount,actionId,nonce,address(this)));
        require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); nonces[actor]=nonce+1;
        executedAt[actionId] = block.number;
        calls += 1;
    }
}
