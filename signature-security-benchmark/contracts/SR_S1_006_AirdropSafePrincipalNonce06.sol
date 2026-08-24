// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropSafePrincipalNonce06 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public airdropPaid;
    mapping(address => uint256) public nonces;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function claimAirdrop(address user, uint256 amount, bytes32 campaign, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[user], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(user, amount, campaign, nonce));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        nonces[user] = nonce + 1;

        airdropPaid[user] += amount;
    }
}
