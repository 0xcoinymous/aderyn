// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BridgeMintMultiDomainCrossChain34 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public bridgedMint;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address recipient, uint256 amount, bytes32 messageId, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[recipient], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(recipient, amount, messageId, nonce));
        _authorize(digest, signature);
        nonces[recipient] = nonce + 1;
        bridgedMint[recipient] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
