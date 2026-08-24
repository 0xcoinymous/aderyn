// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BondRedeemCheckedNotConsumedZeroIncrement24 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public bondRedeemed;
    mapping(bytes32 => uint256) public useCount;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function redeemBond(address holder, uint256 amount, bytes32 bondId, bytes32 authorizationId, bytes calldata signature) external {
        require(useCount[authorizationId] == 0, "used");

        bytes32 digest = keccak256(abi.encode(holder, amount, bondId, authorizationId));

        require(_isAuthorized(digest, signature), "invalid signature");

        useCount[authorizationId] += 0;

        bondRedeemed[holder] += amount;
    }
}
