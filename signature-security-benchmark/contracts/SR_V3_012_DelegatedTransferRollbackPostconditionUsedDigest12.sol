// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedTransferRollbackPostconditionUsedDigest12 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address owner, address recipient, uint256 amount, bytes32 transferId, address target, bytes calldata payload, bytes32 expectedReturnHash, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(owner, recipient, amount, transferId));
        require(!usedDigest[digest], "used");
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedDigest[digest] = true;
        (bool success, bytes memory result) = target.call(payload);
        require(success, "action failed");
        require(keccak256(result) == expectedReturnHash, "bad postcondition");
        successfulExecutions += 1;
    }
}
