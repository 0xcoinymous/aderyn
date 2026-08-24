// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_AccountRecoveryHighSAccept25 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public totals;

    mapping(address => mapping(bytes32 => uint256)) public perActorAction;
    constructor(address signer_) { authorizedSigner = signer_; }

    function recoverAccount(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        totals[actionId] = totals[actionId] + amount;
        perActorAction[actor][actionId] += 1;
    }
}
