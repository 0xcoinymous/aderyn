// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AffiliateRollbackTwoCallsAuthorizationId18 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address affiliate, uint256 amount, bytes32 campaign, bytes32 authorizationId, address targetA, bytes calldata payloadA, address targetB, bytes calldata payloadB, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(affiliate, amount, campaign, authorizationId));
        _authorize(digest, signature);
        usedAuthorization[authorizationId] = true;
        (bool first,) = targetA.call(payloadA);
        require(first, "first failed");
        (bool second,) = targetB.call(payloadB);
        require(second, "second failed");
        successfulExecutions += 1;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
