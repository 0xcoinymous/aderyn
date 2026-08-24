// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RescueSafeAuthorizationId12 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rescued;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function rescueBySig(address recipient, uint256 amount, bytes32 rescueId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, rescueId, authorizationId));

        _authorize(digest, signature);

        usedAuthorization[authorizationId] = true;

        rescued[recipient] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
