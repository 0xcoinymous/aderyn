// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LoanDrawSafeMultiFullBatch08 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedBatch;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeBatch(bytes32 fullBatchHash, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedBatch[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(address(this), fullBatchHash, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        usedBatch[authorizationId] = true;
    }
}
