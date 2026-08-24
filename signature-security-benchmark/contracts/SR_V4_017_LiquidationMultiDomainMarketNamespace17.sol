// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LiquidationMultiDomainMarketNamespace17 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(bytes32 => uint256) public liquidatedDebt;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address account, uint256 debt, bytes32 positionId, bytes32 marketId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[marketId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(account, debt, positionId, authorizationId));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        usedByDomain[marketId][authorizationId] = true;
        liquidatedDebt[positionId] += debt;
    }
}
