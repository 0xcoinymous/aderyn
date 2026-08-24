// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ReferralPayoutNoOneTimeSignedNonce12 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public referralPaid;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payReferral(address referrer, address user, uint256 amount, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(referrer, user, amount, nonce));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        referralPaid[referrer] += amount;
    }
}
