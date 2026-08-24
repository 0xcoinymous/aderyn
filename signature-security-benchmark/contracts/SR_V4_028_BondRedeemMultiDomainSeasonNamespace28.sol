// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BondRedeemMultiDomainSeasonNamespace28 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public bondRedeemed;
    mapping(uint256 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address holder, uint256 amount, bytes32 bondId, uint256 seasonId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[seasonId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(holder, amount, bondId, authorizationId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedByDomain[seasonId][authorizationId] = true;
        bondRedeemed[holder] += amount;
    }
}
