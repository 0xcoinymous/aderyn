// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeRebateCheckedNotConsumedSetFalse03 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public rebates;
    mapping(bytes32 => bool) public used;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function claimRebate(address trader, uint256 amount, uint256 epoch, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(trader, amount, epoch, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        used[authorizationId] = false;

        rebates[trader] += amount;
    }
}
