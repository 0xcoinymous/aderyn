// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_EscrowReleaseSafeAuthorizationId03 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public escrowPaid;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseEscrow(bytes32 escrowId, address beneficiary, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(escrowId, beneficiary, amount, authorizationId));

        _authorize(digest, signature);

        usedAuthorization[authorizationId] = true;

        escrowPaid[escrowId] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
