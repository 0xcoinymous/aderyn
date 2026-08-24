// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_LoanDrawSafeLibraryCanonical17 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    mapping(address => uint256) public cumulativeAmount;
    constructor(address signer_) { authorizedSigner = signer_; }

    function drawBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid");
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
        if (amount != 0) { cumulativeAmount[actor] += amount; }
    }
}
