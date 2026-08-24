// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OracleUpdateMultiDomainCrossFunction11 is SR_ReplayBenchSignerBase {
    mapping(bytes32 => uint256) public prices; mapping(bytes32 => uint256) public updateCount;
    mapping(bytes32 => bool) public usedPrimary;
    mapping(bytes32 => bool) public usedAlternate;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function primary(bytes32 feedId, uint256 price, uint256 reportTime, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedPrimary[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(feedId, price, reportTime, authorizationId));
        require(_isAuthorized(digest, signature), "invalid signature");
        usedPrimary[authorizationId] = true;
        prices[feedId] = price; updateCount[feedId] += 1;
    }

    function alternate(bytes32 feedId, uint256 price, uint256 reportTime, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAlternate[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(feedId, price, reportTime, authorizationId));
        require(_isAuthorized(digest, signature), "invalid signature");
        usedAlternate[authorizationId] = true;
        prices[feedId] = price; updateCount[feedId] += 1;
    }
}
