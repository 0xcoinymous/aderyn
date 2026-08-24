// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ListingRollbackTwoCallsNonce04 is SR_ReplayBenchSignerBase {
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function execute(bytes32 listingId, address buyer, uint256 price, uint256 nonce, address targetA, bytes calldata payloadA, address targetB, bytes calldata payloadB, bytes calldata signature) external {
        require(nonce == nonces[buyer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(listingId, buyer, price, nonce));
        require(_isAuthorized(digest, signature), "invalid signature");
        nonces[buyer] = nonce + 1;
        (bool first,) = targetA.call(payloadA);
        require(first, "first failed");
        (bool second,) = targetB.call(payloadB);
        require(second, "second failed");
        successfulExecutions += 1;
    }
}
