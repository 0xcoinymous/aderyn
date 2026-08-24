// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RfqSafeDomainPurpose10 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public rfqFilled;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function fillRfq(bytes32 quoteId, address maker, address taker, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, keccak256("EXECUTE"), authorizationId));

        _authorize(digest, signature);

        used[authorizationId] = true;

        rfqFilled[quoteId] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
