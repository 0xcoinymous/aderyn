// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_OrderFillAdversarialSafe05 {
    address public immutable authorizedSigner;
    bytes32 public lastObservedSignatureHash;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    constructor(address signer_) { authorizedSigner = signer_; }

    function fillOrder(address actor,address recipient,uint256 amount,bytes32 actionId,uint8 v,bytes32 r,bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); lastObservedSignatureHash=keccak256(abi.encode(r,s,v));
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
    }
}
