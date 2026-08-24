// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RoyaltyRollbackTwoCallsBitmap25 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address creator, uint256 amount, bytes32 saleId, uint256 nonce, address targetA, bytes calldata payloadA, address targetB, bytes calldata payloadB, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[creator][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(creator, amount, saleId, nonce));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        nonceBitmap[creator][word] |= mask;
        (bool first,) = targetA.call(payloadA);
        require(first, "first failed");
        (bool second,) = targetB.call(payloadB);
        require(second, "second failed");
        successfulExecutions += 1;
    }
}
