// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CollateralRollbackPartialSessionUsedDigest14 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address account, address asset, uint256 amount, address firstTarget, bytes calldata firstPayload, address secondTarget, bytes calldata secondPayload, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(account, asset, amount));
        require(!usedDigest[digest], "used");
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        usedDigest[digest] = true;
        (bool first,) = firstTarget.call(firstPayload);
        require(first, "first session call failed");
        (bool second,) = secondTarget.call(secondPayload);
        if (!second) revert("session reverted");
        successfulExecutions += 1;
    }
}
