// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OracleUpdateCheckedNotConsumedWrongMapping07 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public prices; mapping(bytes32 => uint256) public updateCount;
    mapping(bytes32 => bool) public checked; mapping(bytes32 => bool) public consumed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function updatePrice(bytes32 feedId, uint256 price, uint256 reportTime, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!checked[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(feedId, price, reportTime, authorizationId));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        consumed[authorizationId] = true;

        prices[feedId] = price; updateCount[feedId] += 1;
    }
}
