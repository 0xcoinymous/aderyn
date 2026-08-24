// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_GaslessTransferAdversarialSafe01 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;

    constructor(address signer_) { authorizedSigner = signer_; }

    function transferBySig(address actor,address recipient,uint256 amount,bytes32 actionId,uint8 parity,bytes32 r,bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(parity<=1,"parity"); require(SM_MalleabilityBenchLib.recoverParity01(digest,parity,r,s)==authorizedSigner,"invalid");
        completed[actionId] = true;
        completionCount += 1;
    }
}
