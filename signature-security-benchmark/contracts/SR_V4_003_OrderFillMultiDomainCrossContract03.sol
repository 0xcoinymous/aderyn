// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OrderFillMultiDomainCrossContract03 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public filledAmount;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(bytes32 orderId, address maker, address taker, uint256 amount, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(orderId, maker, taker, amount, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        filledAmount[orderId] += amount;
    }
}
