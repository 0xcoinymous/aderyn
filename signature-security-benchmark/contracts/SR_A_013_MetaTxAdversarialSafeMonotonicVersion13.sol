// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_MetaTxAdversarialSafeMonotonicVersion13 {
    address public immutable authorizedSigner;
    uint256 public currentVersion;
    bytes32 public configHash;
    constructor(address signer_) { authorizedSigner = signer_; }
    function setConfig(uint256 version, bytes32 newConfigHash, bytes calldata signature) external {
        require(version > currentVersion, "stale version");
        bytes32 digest = keccak256(abi.encode(address(this), version, newConfigHash));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        currentVersion = version;
        configHash = newConfigHash;
    }
}
