// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CollateralMultiDomainCrossWallet25 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    mapping(address => uint256) public walletNonces;
    mapping(address => uint256) public collateralOut;

    function execute(address account, address asset, uint256 amount, address wallet, uint256 nonce, bytes calldata signature) external {
        require(nonce == walletNonces[wallet], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(account, asset, amount, nonce));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        walletNonces[wallet] = nonce + 1;
        collateralOut[account] += amount;
    }
}
