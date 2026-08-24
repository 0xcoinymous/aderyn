// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ReferralPayoutSafeDomainPurpose04 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public referralPaid;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payReferral(address referrer, address user, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(referrer, user, amount, keccak256("EXECUTE"), authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        used[authorizationId] = true;

        referralPaid[referrer] += amount;
    }
}
