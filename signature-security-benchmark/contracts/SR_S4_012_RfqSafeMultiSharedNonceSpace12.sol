// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RfqSafeMultiSharedNonceSpace12 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public rfqFilled;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function pathA(bytes32 quoteId, address maker, address taker, uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[maker], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, nonce));
        _authorize(digest, signature);
        nonces[maker] = nonce + 1;
        rfqFilled[quoteId] += amount;
    }

    function pathB(bytes32 quoteId, address maker, address taker, uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[maker], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, nonce));
        _authorize(digest, signature);
        nonces[maker] = nonce + 1;
        rfqFilled[quoteId] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
