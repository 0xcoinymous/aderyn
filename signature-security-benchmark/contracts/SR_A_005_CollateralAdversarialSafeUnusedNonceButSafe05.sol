// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CollateralAdversarialSafeUnusedNonceButSafe05 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public collateralOut;
    uint256 public nonce; mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawCollateral(address account, address asset, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(account, asset, amount, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        usedAuthorization[authorizationId] = true;

        collateralOut[account] += amount;
    }
}
