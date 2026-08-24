// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BatchPaymentMultiDomainMarketNamespace37 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public batchPaid;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address payer, bytes32 batchId, uint256 total, bytes32 marketId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[marketId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(payer, batchId, total, authorizationId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedByDomain[marketId][authorizationId] = true;
        batchPaid[payer] += total;
    }
}
