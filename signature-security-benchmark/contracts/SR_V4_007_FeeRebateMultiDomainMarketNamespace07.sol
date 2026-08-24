// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeRebateMultiDomainMarketNamespace07 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rebates;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address trader, uint256 amount, uint256 epoch, bytes32 marketId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[marketId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(trader, amount, epoch, authorizationId));
        _authorize(digest, signature);
        usedByDomain[marketId][authorizationId] = true;
        rebates[trader] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
