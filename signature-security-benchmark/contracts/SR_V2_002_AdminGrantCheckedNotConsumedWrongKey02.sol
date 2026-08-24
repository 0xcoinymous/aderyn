// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AdminGrantCheckedNotConsumedWrongKey02 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public roles;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function grantBySig(address account, uint256 role, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(account, role, authorizationId));

        _authorize(digest, signature);

        used[keccak256(abi.encode(msg.sender, authorizationId))] = true;

        roles[account] = role;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
