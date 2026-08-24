// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AccountRecoveryMultiDomainCrossWallet35 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    mapping(address => uint256) public walletNonces;
    mapping(address => address) public owners; mapping(address => uint256) public recoveryCount;

    function execute(address account, address newOwner, bytes32 recoveryId, address wallet, uint256 nonce, bytes calldata signature) external {
        require(nonce == walletNonces[wallet], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(account, newOwner, recoveryId, nonce));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        walletNonces[wallet] = nonce + 1;
        owners[account] = newOwner; recoveryCount[account] += 1;
    }
}
