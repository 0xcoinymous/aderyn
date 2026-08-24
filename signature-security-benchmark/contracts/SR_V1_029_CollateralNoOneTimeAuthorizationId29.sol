// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CollateralNoOneTimeAuthorizationId29 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public collateralOut;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawCollateral(address account, address asset, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(account, asset, amount, authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        collateralOut[account] += amount;
    }
}
