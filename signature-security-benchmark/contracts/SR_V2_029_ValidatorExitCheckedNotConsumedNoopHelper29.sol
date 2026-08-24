// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ValidatorExitCheckedNotConsumedNoopHelper29 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public validatorExited;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function exitValidator(address validator, uint256 amount, bytes32 exitId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(validator, amount, exitId, authorizationId));

        _authorize(digest, signature);

        _consume(authorizationId);

        validatorExited[validator] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }

    function _consume(bytes32) internal pure {}
}
