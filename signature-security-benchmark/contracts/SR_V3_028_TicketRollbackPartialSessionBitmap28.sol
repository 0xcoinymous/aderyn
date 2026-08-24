// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TicketRollbackPartialSessionBitmap28 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address user, uint256 amount, bytes32 ticketId, uint256 nonce, address firstTarget, bytes calldata firstPayload, address secondTarget, bytes calldata secondPayload, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[user][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(user, amount, ticketId, nonce));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        nonceBitmap[user][word] |= mask;
        (bool first,) = firstTarget.call(firstPayload);
        require(first, "first session call failed");
        (bool second,) = secondTarget.call(secondPayload);
        if (!second) revert("session reverted");
        successfulExecutions += 1;
    }
}
