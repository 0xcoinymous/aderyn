// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RefundMultiDomainSeasonNamespace38 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public refunded;
    mapping(uint256 => mapping(uint256 => uint256)) public usedBitmapBySeason;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function execute(address user, uint256 amount, bytes32 refundId, uint256 seasonId, uint256 authorizationNumber, bytes calldata signature) external {
        uint256 word = authorizationNumber >> 8;
        uint256 mask = uint256(1) << (authorizationNumber & 255);
        require(usedBitmapBySeason[seasonId][word] & mask == 0, "used");

        // Vulnerable: seasonId namespaces replay state but is absent from the signature.
        bytes32 digest = keccak256(abi.encode(user, amount, refundId, authorizationNumber));
        require(_isAuthorized(digest, signature), "invalid signature");

        usedBitmapBySeason[seasonId][word] |= mask;
        refunded[user] += amount;
    }
}
