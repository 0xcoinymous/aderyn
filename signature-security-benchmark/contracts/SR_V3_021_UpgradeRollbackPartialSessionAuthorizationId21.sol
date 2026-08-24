// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_UpgradeRollbackPartialSessionAuthorizationId21 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address implementation, bytes32 codeHash, uint256 version, bytes32 authorizationId, address firstTarget, bytes calldata firstPayload, address secondTarget, bytes calldata secondPayload, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(implementation, codeHash, version, authorizationId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedAuthorization[authorizationId] = true;
        (bool first,) = firstTarget.call(firstPayload);
        require(first, "first session call failed");
        (bool second,) = secondTarget.call(secondPayload);
        if (!second) revert("session reverted");
        successfulExecutions += 1;
    }
}
