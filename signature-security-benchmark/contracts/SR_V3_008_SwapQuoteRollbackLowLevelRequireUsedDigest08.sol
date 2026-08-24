// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SwapQuoteRollbackLowLevelRequireUsedDigest08 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address trader, address tokenOut, uint256 amountOut, bytes32 quoteId, address target, bytes calldata payload, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(trader, tokenOut, amountOut, quoteId));
        require(!usedDigest[digest], "used");
        require(_verifySignature(digest, signature), "invalid signature");
        usedDigest[digest] = true;
        (bool success,) = target.call(payload);
        require(success, "action failed");
        successfulExecutions += 1;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
