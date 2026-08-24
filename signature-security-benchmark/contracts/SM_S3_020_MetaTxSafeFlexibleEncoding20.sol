// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_MetaTxSafeFlexibleEncoding20 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    uint256 public parityCounter;
    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        bytes32 messageKey=keccak256(abi.encode(actor,recipient,amount,actionId,address(this))); require(!usedAuthorization[messageKey],"used"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); usedAuthorization[messageKey]=true;
        executedAt[actionId] = block.number;
        calls += 1;
        parityCounter += amount & 1;
    }
}
