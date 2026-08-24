// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_LiquidationSafeFlexibleEncoding16 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(bytes32 => uint256) public totals;

    constructor(address signer_) { authorizedSigner = signer_; }

    function liquidateBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        bytes32 messageKey=keccak256(abi.encode(actor,recipient,amount,actionId,address(this))); require(!usedAuthorization[messageKey],"used"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); usedAuthorization[messageKey]=true;
        totals[actionId] = totals[actionId] + amount;
    }
}
