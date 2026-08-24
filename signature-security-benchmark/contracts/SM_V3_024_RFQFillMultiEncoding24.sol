// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RFQFillMultiEncoding24 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    mapping(bytes32 => bool) public shadowConsumed;
    constructor(address signer_) { authorizedSigner = signer_; }

    function fillRfq(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(signature.length == 64 || signature.length == 65, "length"); bytes32 encodingKey=keccak256(abi.encode(signature.length, signature)); require(!usedEncoding[encodingKey],"used"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); usedEncoding[encodingKey]=true;
        executedAt[actionId] = block.number;
        calls += 1;
        shadowConsumed[keccak256(abi.encode(actionId, actor))] = true;
    }
}
