// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ListingNoOneTimeDeadline19 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public sales;

    constructor(address signer_) { authorizedSigner = signer_; }

    function acceptListing(bytes32 listingId, address buyer, uint256 price, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(listingId, buyer, price, deadline));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        sales[listingId] += price;
    }
}
