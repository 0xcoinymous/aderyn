// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropMultiDomainCrossPurpose12 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public airdropPaid;
    mapping(bytes32 => bool) public executed;
    mapping(bytes32 => bool) public cancelled;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeAuthorization(address user, uint256 amount, bytes32 campaign, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!executed[authorizationId], "executed");
        bytes32 digest = keccak256(abi.encode(user, amount, campaign, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        executed[authorizationId] = true;
        airdropPaid[user] += amount;
    }

    function cancelAuthorization(address user, uint256 amount, bytes32 campaign, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!cancelled[authorizationId], "cancelled");
        bytes32 digest = keccak256(abi.encode(user, amount, campaign, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        cancelled[authorizationId] = true;
    }
}
