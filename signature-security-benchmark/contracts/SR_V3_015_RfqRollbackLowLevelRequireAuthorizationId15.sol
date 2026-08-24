// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RfqRollbackLowLevelRequireAuthorizationId15 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(bytes32 quoteId, address maker, address taker, uint256 amount, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        usedAuthorization[authorizationId] = true;
        (bool success,) = target.call(payload);
        require(success, "action failed");
        successfulExecutions += 1;
    }
}
