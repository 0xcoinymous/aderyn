// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SessionSpendSafeAuthorizationId05 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => uint256) public sessionSpent;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address wallet_) { wallet = wallet_; }

    function spendSession(address session, address recipient, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(session, recipient, amount, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        usedAuthorization[authorizationId] = true;

        sessionSpent[session] += amount;
    }
}
