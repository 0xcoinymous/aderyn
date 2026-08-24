// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeWithdrawCheckedNotConsumedBitmapWrongBit26 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public feeWithdrawn;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawFees(address recipient, uint256 amount, bytes32 feeId, bytes32 authorizationId, bytes calldata signature) external {
        uint256 word = uint256(authorizationId) >> 8;
        uint256 bit = uint256(authorizationId) & 255;
        uint256 mask = uint256(1) << bit;
        require(nonceBitmap[recipient][word] & mask == 0, "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, feeId, authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        nonceBitmap[recipient][word] |= uint256(1) << ((bit + 1) & 255);

        feeWithdrawn[recipient] += amount;
    }
}
