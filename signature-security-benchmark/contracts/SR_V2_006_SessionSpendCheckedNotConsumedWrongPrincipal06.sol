// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SessionSpendCheckedNotConsumedWrongPrincipal06 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public sessionSpent;
    mapping(address => mapping(bytes32 => bool)) public usedBySigner;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function spendSession(address session, address recipient, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedBySigner[session][authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(session, recipient, amount, authorizationId));

        require(_isAuthorized(digest, signature), "invalid signature");

        usedBySigner[msg.sender][authorizationId] = true;

        sessionSpent[session] += amount;
    }
}
