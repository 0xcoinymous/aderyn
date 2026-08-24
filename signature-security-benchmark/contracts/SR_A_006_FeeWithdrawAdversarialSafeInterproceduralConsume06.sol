// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeWithdrawAdversarialSafeInterproceduralConsume06 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public feeWithdrawn;
    mapping(bytes32 => bool) private used;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function withdrawFees(address recipient, uint256 amount, bytes32 feeId, bytes32 authorizationId, bytes calldata signature) external {
        require(!_isUsed(authorizationId), "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, feeId, authorizationId));

        require(_isAuthorized(digest, signature), "invalid signature");

        _consume(authorizationId);

        feeWithdrawn[recipient] += amount;
    }


    function _isUsed(bytes32 id) internal view returns (bool) { return used[id]; }
    function _consume(bytes32 id) internal { used[id] = true; }
}
