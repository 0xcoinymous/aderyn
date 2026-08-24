// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SessionSpendSafeMultiSignedMarket04 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public sessionSpent;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function spendSession(address session, address recipient, uint256 amount, bytes32 marketId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[marketId][authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(session, recipient, amount, marketId, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        usedByDomain[marketId][authorizationId] = true;

        sessionSpent[session] += amount;
    }
}
