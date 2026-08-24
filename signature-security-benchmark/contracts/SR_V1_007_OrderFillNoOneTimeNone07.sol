// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OrderFillNoOneTimeNone07 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(bytes32 => uint256) public filledAmount;

    constructor(address wallet_) { wallet = wallet_; }

    function fillOrder(bytes32 orderId, address maker, address taker, uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(orderId, maker, taker, amount));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        filledAmount[orderId] += amount;
    }
}
