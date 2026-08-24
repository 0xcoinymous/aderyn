// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BondRedeemRollbackDelegatecallAssertAuthorizationId17 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address holder, uint256 amount, bytes32 bondId, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(holder, amount, bondId, authorizationId));
        require(_verifySignature(digest, signature), "invalid signature");
        usedAuthorization[authorizationId] = true;
        (bool success,) = target.delegatecall(payload);
        assert(success);
        successfulExecutions += 1;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
