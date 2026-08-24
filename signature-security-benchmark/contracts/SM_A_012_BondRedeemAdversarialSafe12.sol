// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BondRedeemAdversarialSafe12 {
    address public immutable authorizedSigner;
    mapping(address=>uint256) public nonces;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    mapping(bytes32 => bool) public shadowConsumed;
    constructor(address signer_) { authorizedSigner = signer_; }

    function redeemBySig(address actor,address recipient,uint256 amount,bytes32 actionId,bytes calldata signature) external {
        uint256 nonce=nonces[actor]; bytes32 digest=keccak256(abi.encode(actor,recipient,amount,actionId,nonce,address(this)));
        require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); nonces[actor]=nonce+1;
        executedAt[actionId] = block.number;
        calls += 1;
        shadowConsumed[keccak256(abi.encode(actionId, actor))] = true;
    }
}
