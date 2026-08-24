// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_MetaTxRollbackTwoCallsUsedDigest11 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address wallet_) { wallet = wallet_; }

    function execute(address user, address target, uint256 value, bytes32 callHash, address targetA, bytes calldata payloadA, address targetB, bytes calldata payloadB, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(user, target, value, callHash));
        require(!usedDigest[digest], "used");
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        usedDigest[digest] = true;
        (bool first,) = targetA.call(payloadA);
        require(first, "first failed");
        (bool second,) = targetB.call(payloadB);
        require(second, "second failed");
        successfulExecutions += 1;
    }
}
