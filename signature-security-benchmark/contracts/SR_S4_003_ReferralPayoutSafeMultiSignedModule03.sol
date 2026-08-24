// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ReferralPayoutSafeMultiSignedModule03 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public referralPaid;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payReferral(address referrer, address user, uint256 amount, bytes32 moduleId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[moduleId][authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(referrer, user, amount, moduleId, authorizationId));

        _authorize(digest, signature);

        usedByDomain[moduleId][authorizationId] = true;

        referralPaid[referrer] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
