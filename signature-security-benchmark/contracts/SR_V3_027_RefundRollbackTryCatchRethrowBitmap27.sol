// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RefundRollbackTryCatchRethrowBitmap27 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address user, uint256 amount, bytes32 refundId, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[user][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(user, amount, refundId, nonce));
        _authorize(digest, signature);
        nonceBitmap[user][word] |= mask;
        try SR_IReplayBenchAction(target).run(payload) returns (bool ok) {
            require(ok, "action returned false");
        } catch {
            revert("action reverted");
        }
        successfulExecutions += 1;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
