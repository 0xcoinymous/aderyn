// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_WithdrawalRawSignatureKey02 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(bytes32 => uint256) public totals;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(abi.encode(signature));
        require(!consumedSignature[key], "signature used");
        require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        totals[actionId] = totals[actionId] + amount;
    }
}
