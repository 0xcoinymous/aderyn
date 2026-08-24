// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_WithdrawalSafeAuthorizationId01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public withdrawn;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawBySig(address user, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(user, amount, authorizationId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        usedAuthorization[authorizationId] = true;

        withdrawn[user] += amount;
    }
}
