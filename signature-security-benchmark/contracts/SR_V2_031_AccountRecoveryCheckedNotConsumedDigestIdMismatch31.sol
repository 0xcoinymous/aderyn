// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AccountRecoveryCheckedNotConsumedDigestIdMismatch31 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => address) public owners; mapping(address => uint256) public recoveryCount;
    mapping(bytes32 => bool) public used;

    constructor(address wallet_) { wallet = wallet_; }

    function recoverAccount(address account, address newOwner, bytes32 recoveryId, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(account, newOwner, recoveryId, authorizationId));

        require(!used[digest], "used");

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        used[authorizationId] = true;

        owners[account] = newOwner; recoveryCount[account] += 1;
    }
}
