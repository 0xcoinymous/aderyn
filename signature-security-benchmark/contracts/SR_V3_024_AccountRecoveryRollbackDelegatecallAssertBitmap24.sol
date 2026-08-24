// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AccountRecoveryRollbackDelegatecallAssertBitmap24 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address account, address newOwner, bytes32 recoveryId, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[account][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(account, newOwner, recoveryId, nonce));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        nonceBitmap[account][word] |= mask;
        (bool success,) = target.delegatecall(payload);
        assert(success);
        successfulExecutions += 1;
    }
}
