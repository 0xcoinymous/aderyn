// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OracleUpdateSafeDomainVersion05 is SR_ReplayBenchSignerBase {
    mapping(bytes32 => uint256) public prices; mapping(bytes32 => uint256) public updateCount;
    mapping(bytes32 => bool) public used; uint256 public constant PROTOCOL_VERSION = 3;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function updatePrice(bytes32 feedId, uint256 price, uint256 reportTime, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(feedId, price, reportTime, PROTOCOL_VERSION, authorizationId));

        require(_isAuthorized(digest, signature), "invalid signature");

        used[authorizationId] = true;

        prices[feedId] = price; updateCount[feedId] += 1;
    }
}
