// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropCheckedNotConsumedZeroIncrement08 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public airdropPaid;
    mapping(bytes32 => uint256) public useCount;

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimAirdrop(address user, uint256 amount, bytes32 campaign, bytes32 authorizationId, bytes calldata signature) external {
        require(useCount[authorizationId] == 0, "used");

        bytes32 digest = keccak256(abi.encode(user, amount, campaign, authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        useCount[authorizationId] += 0;

        airdropPaid[user] += amount;
    }
}
