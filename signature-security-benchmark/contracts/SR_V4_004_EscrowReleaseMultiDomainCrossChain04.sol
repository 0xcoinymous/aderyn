// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_EscrowReleaseMultiDomainCrossChain04 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public escrowPaid;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(bytes32 escrowId, address beneficiary, uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[beneficiary], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(escrowId, beneficiary, amount, nonce));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        nonces[beneficiary] = nonce + 1;
        escrowPaid[escrowId] += amount;
    }
}
