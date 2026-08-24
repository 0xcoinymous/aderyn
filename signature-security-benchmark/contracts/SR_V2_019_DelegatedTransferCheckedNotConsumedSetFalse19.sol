// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedTransferCheckedNotConsumedSetFalse19 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public delegatedSent;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function delegatedTransfer(address owner, address recipient, uint256 amount, bytes32 transferId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(owner, recipient, amount, transferId, authorizationId));

        require(_verifySignature(digest, signature), "invalid signature");

        used[authorizationId] = false;

        delegatedSent[owner] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
