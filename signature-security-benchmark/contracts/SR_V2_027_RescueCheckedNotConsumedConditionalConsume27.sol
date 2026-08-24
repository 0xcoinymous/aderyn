// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RescueCheckedNotConsumedConditionalConsume27 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rescued;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function rescueBySig(address recipient, uint256 amount, bytes32 rescueId, bytes32 authorizationId, bool markUsed, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, rescueId, authorizationId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        if (markUsed) { used[authorizationId] = true; }

        rescued[recipient] += amount;
    }
}
