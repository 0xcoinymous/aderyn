// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VaultHarvestCheckedNotConsumedWrongMapping23 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public harvested;
    mapping(bytes32 => bool) public checked; mapping(bytes32 => bool) public consumed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function harvestBySig(address vault, uint256 amount, bytes32 harvestId, bytes32 authorizationId, bytes calldata signature) external {
        require(!checked[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(vault, amount, harvestId, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        consumed[authorizationId] = true;

        harvested[vault] += amount;
    }
}
