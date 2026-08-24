// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_EscrowReleaseNoOneTimeNone08 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public escrowPaid;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseEscrow(bytes32 escrowId, address beneficiary, uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(escrowId, beneficiary, amount));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        escrowPaid[escrowId] += amount;
    }
}
