// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ValidatorExitRollbackLowLevelRequireBitmap22 is SR_ReplayBenchSignerBase {
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function execute(address validator, uint256 amount, bytes32 exitId, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[validator][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(validator, amount, exitId, nonce));
        require(_isAuthorized(digest, signature), "invalid signature");
        nonceBitmap[validator][word] |= mask;
        (bool success,) = target.call(payload);
        require(success, "action failed");
        successfulExecutions += 1;
    }
}
