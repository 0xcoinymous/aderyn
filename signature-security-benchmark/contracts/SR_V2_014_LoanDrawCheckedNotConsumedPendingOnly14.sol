// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LoanDrawCheckedNotConsumedPendingOnly14 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public facilityDrawn;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public pending;

    constructor(address signer_) { authorizedSigner = signer_; }

    function drawLoan(address borrower, uint256 amount, bytes32 facilityId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(borrower, amount, facilityId, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        pending[authorizationId] = true;

        facilityDrawn[facilityId] += amount;
    }
}
