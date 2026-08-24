// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TreasuryCheckedNotConsumedBitmapMissing09 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public treasuryPaid;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payInvoice(address recipient, uint256 amount, bytes32 invoice, bytes32 authorizationId, bytes calldata signature) external {
        uint256 word = uint256(authorizationId) >> 8;
        uint256 mask = uint256(1) << (uint256(authorizationId) & 255);
        require(nonceBitmap[recipient][word] & mask == 0, "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, invoice, authorizationId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        treasuryPaid[recipient] += amount;
    }
}
