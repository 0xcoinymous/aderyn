// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedTransferMultiDomainCrossContract23 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public delegatedSent;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address owner, address recipient, uint256 amount, bytes32 transferId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(owner, recipient, amount, transferId, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        delegatedSent[owner] += amount;
    }
}
