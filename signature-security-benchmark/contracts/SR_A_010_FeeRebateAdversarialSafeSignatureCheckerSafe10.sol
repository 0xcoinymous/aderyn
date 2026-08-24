// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeRebateAdversarialSafeSignatureCheckerSafe10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rebates;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRebate(address trader, uint256 amount, uint256 epoch, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[trader], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(trader, amount, epoch, nonce));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        nonces[trader] = nonce + 1;

        rebates[trader] += amount;
    }
}
