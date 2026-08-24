// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_EscrowReleaseSafeMultiSharedRegistry01 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public escrowPaid;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function primary(bytes32 escrowId, address beneficiary, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(escrowId, beneficiary, amount, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        escrowPaid[escrowId] += amount;
    }

    function alternate(bytes32 escrowId, address beneficiary, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(escrowId, beneficiary, amount, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        escrowPaid[escrowId] += amount;
    }
}
