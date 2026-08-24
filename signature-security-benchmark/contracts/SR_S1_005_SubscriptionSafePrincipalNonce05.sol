// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SubscriptionSafePrincipalNonce05 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public charged;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function chargeSubscription(address subscriber, uint256 amount, uint256 period, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[subscriber], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(subscriber, amount, period, nonce));

        _authorize(digest, signature);

        nonces[subscriber] = nonce + 1;

        charged[subscriber] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
