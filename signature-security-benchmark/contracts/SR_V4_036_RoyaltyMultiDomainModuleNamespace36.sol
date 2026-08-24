// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RoyaltyMultiDomainModuleNamespace36 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    address public immutable wallet;
    mapping(address => uint256) public royalties;
    mapping(bytes32 => mapping(bytes32 => uint256)) public consumedAtBlockByModule;

    constructor(address wallet_) { wallet = wallet_; }

    function execute(address creator, uint256 amount, bytes32 saleId, bytes32 moduleId, bytes32 authorizationId, bytes calldata signature) external {
        require(consumedAtBlockByModule[moduleId][authorizationId] == 0, "used");

        // Vulnerable: moduleId scopes consumption state but is omitted from the signed digest.
        bytes32 digest = keccak256(abi.encode(creator, amount, saleId, authorizationId));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        consumedAtBlockByModule[moduleId][authorizationId] = block.number;
        royalties[creator] += amount;
    }
}
