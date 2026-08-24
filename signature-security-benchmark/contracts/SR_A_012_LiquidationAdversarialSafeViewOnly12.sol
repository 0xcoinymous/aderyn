// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LiquidationAdversarialSafeViewOnly12 {
    address public immutable authorizedSigner;
    constructor(address signer_) { authorizedSigner = signer_; }
    function isAuthorized(bytes32 messageHash, bytes calldata signature) external view returns (bool) {
        return SR_ReplayBenchECDSA.recover(messageHash, signature) == authorizedSigner;
    }
}
