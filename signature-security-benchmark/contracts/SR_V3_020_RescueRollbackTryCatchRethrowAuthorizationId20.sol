// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RescueRollbackTryCatchRethrowAuthorizationId20 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address wallet_) { wallet = wallet_; }

    function execute(address recipient, uint256 amount, bytes32 rescueId, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, rescueId, authorizationId));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        usedAuthorization[authorizationId] = true;
        try SR_IReplayBenchAction(target).run(payload) returns (bool ok) {
            require(ok, "action returned false");
        } catch {
            revert("action reverted");
        }
        successfulExecutions += 1;
    }
}
