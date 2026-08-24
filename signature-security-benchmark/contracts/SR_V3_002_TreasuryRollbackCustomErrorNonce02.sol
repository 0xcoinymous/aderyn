// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TreasuryRollbackCustomErrorNonce02 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;
    error ExternalActionFailed();

    constructor(address wallet_) { wallet = wallet_; }

    function execute(address recipient, uint256 amount, bytes32 invoice, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        require(nonce == nonces[recipient], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(recipient, amount, invoice, nonce));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        nonces[recipient] = nonce + 1;
        (bool success,) = target.call(payload);
        if (!success) revert ExternalActionFailed();
        successfulExecutions += 1;
    }
}
