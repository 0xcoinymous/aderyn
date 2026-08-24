// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ListingSafePrincipalNonce07 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(bytes32 => uint256) public sales;
    mapping(address => uint256) public nonces;

    constructor(address wallet_) { wallet = wallet_; }

    function acceptListing(bytes32 listingId, address buyer, uint256 price, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[buyer], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(listingId, buyer, price, nonce));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        nonces[buyer] = nonce + 1;

        sales[listingId] += price;
    }
}
