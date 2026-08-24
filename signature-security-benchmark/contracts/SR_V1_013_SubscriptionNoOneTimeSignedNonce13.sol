// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SubscriptionNoOneTimeSignedNonce13 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public charged;

    constructor(address signer_) { authorizedSigner = signer_; }

    function chargeSubscription(address subscriber, uint256 amount, uint256 period, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(subscriber, amount, period, nonce));

        require(_verifySignature(digest, signature), "invalid signature");

        charged[subscriber] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
