// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TreasuryMultiDomainCrossContract13 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public treasuryPaid;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address recipient, uint256 amount, bytes32 invoice, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, invoice, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        treasuryPaid[recipient] += amount;
    }
}
