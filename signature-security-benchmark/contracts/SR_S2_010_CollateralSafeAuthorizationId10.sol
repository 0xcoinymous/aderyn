// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CollateralSafeAuthorizationId10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public collateralOut;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawCollateral(address account, address asset, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(account, asset, amount, authorizationId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        usedAuthorization[authorizationId] = true;

        collateralOut[account] += amount;
    }
}
