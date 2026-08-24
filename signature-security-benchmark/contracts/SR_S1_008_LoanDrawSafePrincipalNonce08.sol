// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LoanDrawSafePrincipalNonce08 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public facilityDrawn;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function drawLoan(address borrower, uint256 amount, bytes32 facilityId, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[borrower], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(borrower, amount, facilityId, nonce));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        nonces[borrower] = nonce + 1;

        facilityDrawn[facilityId] += amount;
    }
}
