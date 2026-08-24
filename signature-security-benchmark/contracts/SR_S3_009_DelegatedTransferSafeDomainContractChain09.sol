// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedTransferSafeDomainContractChain09 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public delegatedSent;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function delegatedTransfer(address owner, address recipient, uint256 amount, bytes32 transferId, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[owner], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(owner, recipient, amount, transferId, address(this), block.chainid, nonce));

        require(_verifySignature(digest, signature), "invalid signature");

        nonces[owner] = nonce + 1;

        delegatedSent[owner] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
