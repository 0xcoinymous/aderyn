// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BridgeMintRollbackCustomErrorBitmap23 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;
    error ExternalActionFailed();

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address recipient, uint256 amount, bytes32 messageId, uint256 nonce, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[recipient][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, messageId, nonce));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        nonceBitmap[recipient][word] |= mask;
        (bool success,) = target.call(payload);
        if (!success) revert ExternalActionFailed();
        successfulExecutions += 1;
    }
}
