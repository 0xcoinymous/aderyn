// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ListingCheckedNotConsumedConditionalConsume11 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public sales;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function acceptListing(bytes32 listingId, address buyer, uint256 price, bytes32 authorizationId, bool markUsed, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(listingId, buyer, price, authorizationId));

        _authorize(digest, signature);

        if (markUsed) { used[authorizationId] = true; }

        sales[listingId] += price;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
