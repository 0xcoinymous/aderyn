// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TreasuryNoOneTimeDeadline17 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public treasuryPaid;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payInvoice(address recipient, uint256 amount, bytes32 invoice, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(recipient, amount, invoice, deadline));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        treasuryPaid[recipient] += amount;
    }
}
