// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeRebateNoOneTimeSignedNonce11 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rebates;

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRebate(address trader, uint256 amount, uint256 epoch, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(trader, amount, epoch, nonce));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        rebates[trader] += amount;
    }
}
