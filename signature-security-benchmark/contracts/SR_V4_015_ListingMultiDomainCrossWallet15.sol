// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ListingMultiDomainCrossWallet15 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    mapping(address => uint256) public walletNonces;
    mapping(bytes32 => uint256) public sales;

    function execute(bytes32 listingId, address buyer, uint256 price, address account, uint256 nonce, bytes calldata signature) external {
        require(nonce == walletNonces[account], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(listingId, buyer, price, nonce));
        require(SR_IReplayBench1271(account).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        walletNonces[account] = nonce + 1;
        sales[listingId] += price;
    }
}
