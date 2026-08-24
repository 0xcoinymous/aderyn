// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_UpgradeAdversarialSafePendingAmountZeroed15 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public pending;
    mapping(address => uint256) public paid;
    constructor(address signer_) { authorizedSigner = signer_; }
    function seed(bytes32 escrowId, uint256 amount) external { require(pending[escrowId] == 0); pending[escrowId] = amount; }
    function release(bytes32 escrowId, address beneficiary, uint256 amount, bytes calldata signature) external {
        require(pending[escrowId] == amount && amount != 0, "not pending");
        bytes32 digest = keccak256(abi.encode(address(this), escrowId, beneficiary, amount));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        pending[escrowId] = 0;
        paid[beneficiary] += amount;
    }
}
