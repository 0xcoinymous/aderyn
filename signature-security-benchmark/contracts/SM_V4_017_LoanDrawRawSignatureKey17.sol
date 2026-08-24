// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_LoanDrawRawSignatureKey17 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(address => uint256) public credited;

    uint256 public auditCount;
    constructor(address signer_) { authorizedSigner = signer_; }

    function drawBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(signature);
        require(!consumedSignature[key], "signature used");
        if (v < 27) v += 27; require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        credited[recipient] += amount;
        auditCount += 1;
    }
}
