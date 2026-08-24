// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_TreasuryPaymentSafeLibraryCanonical19 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public credited;

    mapping(bytes32 => bool) public pendingFlag;
    constructor(address signer_) { authorizedSigner = signer_; }

    function payBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        address recovered=SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s); if(recovered!=authorizedSigner) revert("invalid");
        credited[recipient] += amount;
        pendingFlag[actionId] = true;
                delete pendingFlag[actionId];
    }
}
