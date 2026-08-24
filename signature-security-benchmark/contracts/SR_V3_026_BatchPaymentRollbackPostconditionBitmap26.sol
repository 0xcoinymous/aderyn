// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BatchPaymentRollbackPostconditionBitmap26 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address payer, bytes32 batchId, uint256 total, uint256 nonce, address target, bytes calldata payload, bytes32 expectedReturnHash, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[payer][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(payer, batchId, total, nonce));
        require(_verifySignature(digest, signature), "invalid signature");
        nonceBitmap[payer][word] |= mask;
        (bool success, bytes memory result) = target.call(payload);
        require(success, "action failed");
        require(keccak256(result) == expectedReturnHash, "bad postcondition");
        successfulExecutions += 1;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
