// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ReferralPayoutMultiDomainSeasonNamespace08 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public referralPaid;
    mapping(uint256 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address referrer, address user, uint256 amount, uint256 seasonId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[seasonId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(referrer, user, amount, authorizationId));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        usedByDomain[seasonId][authorizationId] = true;
        referralPaid[referrer] += amount;
    }
}
