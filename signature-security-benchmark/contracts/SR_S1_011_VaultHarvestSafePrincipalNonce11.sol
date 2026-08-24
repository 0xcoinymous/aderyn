// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VaultHarvestSafePrincipalNonce11 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public harvested;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function harvestBySig(address vault, uint256 amount, bytes32 harvestId, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[vault], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(vault, amount, harvestId, nonce));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        nonces[vault] = nonce + 1;

        harvested[vault] += amount;
    }
}
