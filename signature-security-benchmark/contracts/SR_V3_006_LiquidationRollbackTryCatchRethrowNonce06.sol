// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LiquidationRollbackTryCatchRethrowNonce06 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address account, uint256 debt, bytes32 positionId, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        require(nonce == nonces[account], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(account, debt, positionId, nonce));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        nonces[account] = nonce + 1;
        try SR_IReplayBenchAction(target).run(payload) returns (bool ok) {
            require(ok, "action returned false");
        } catch {
            revert("action reverted");
        }
        successfulExecutions += 1;
    }
}
