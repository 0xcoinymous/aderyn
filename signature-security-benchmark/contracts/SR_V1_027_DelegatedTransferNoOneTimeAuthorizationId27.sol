// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedTransferNoOneTimeAuthorizationId27 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public delegatedSent;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function delegatedTransfer(address owner, address recipient, uint256 amount, bytes32 transferId, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(owner, recipient, amount, transferId, authorizationId));

        require(_isAuthorized(digest, signature), "invalid signature");

        delegatedSent[owner] += amount;
    }
}
