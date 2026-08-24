// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeWithdrawSafePrincipalNonce12 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public feeWithdrawn;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawFees(address recipient, uint256 amount, bytes32 feeId, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[recipient], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(recipient, amount, feeId, nonce));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        nonces[recipient] = nonce + 1;

        feeWithdrawn[recipient] += amount;
    }
}
