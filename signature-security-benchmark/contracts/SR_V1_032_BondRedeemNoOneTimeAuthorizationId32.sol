// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BondRedeemNoOneTimeAuthorizationId32 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public bondRedeemed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function redeemBond(address holder, uint256 amount, bytes32 bondId, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(holder, amount, bondId, authorizationId));

        _authorize(digest, signature);

        bondRedeemed[holder] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
