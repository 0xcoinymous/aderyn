// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_UpgradeSafeDomainSalt12 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    address public currentImplementation; uint256 public upgradeCount;
    mapping(bytes32 => bool) public used; bytes32 public constant DOMAIN_SALT = keccak256("REPLAY_BENCH_DOMAIN");

    constructor(address wallet_) { wallet = wallet_; }

    function upgradeBySig(address implementation, bytes32 codeHash, uint256 version, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(implementation, codeHash, version, DOMAIN_SALT, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        used[authorizationId] = true;

        currentImplementation = implementation; upgradeCount += 1;
    }
}
