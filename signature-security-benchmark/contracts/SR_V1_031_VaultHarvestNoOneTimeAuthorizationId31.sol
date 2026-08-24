// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VaultHarvestNoOneTimeAuthorizationId31 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public harvested;

    constructor(address signer_) { authorizedSigner = signer_; }

    function harvestBySig(address vault, uint256 amount, bytes32 harvestId, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(vault, amount, harvestId, authorizationId));

        require(_verifySignature(digest, signature), "invalid signature");

        harvested[vault] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
