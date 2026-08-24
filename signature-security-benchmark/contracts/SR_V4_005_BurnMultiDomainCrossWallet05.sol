// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BurnMultiDomainCrossWallet05 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    mapping(address => uint256) public walletNonces;
    mapping(address => uint256) public burned;

    function execute(address holder, uint256 amount, address account, uint256 nonce, bytes calldata signature) external {
        require(nonce == walletNonces[account], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(holder, amount, nonce));
        require(SR_IReplayBench1271(account).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        walletNonces[account] = nonce + 1;
        burned[holder] += amount;
    }
}
