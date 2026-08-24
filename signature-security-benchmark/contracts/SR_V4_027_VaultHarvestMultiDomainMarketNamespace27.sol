// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VaultHarvestMultiDomainMarketNamespace27 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => uint256) public harvested;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address wallet_) { wallet = wallet_; }

    function execute(address vault, uint256 amount, bytes32 harvestId, bytes32 marketId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[marketId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(vault, amount, harvestId, authorizationId));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        usedByDomain[marketId][authorizationId] = true;
        harvested[vault] += amount;
    }
}
