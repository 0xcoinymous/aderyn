// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ListingAdversarialSafeBitmapNonce03 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function transfer(address owner, address recipient, uint256 amount, uint256 nonce, bytes calldata signature) external {
        uint256 word = nonce >> 8;
        uint256 mask = uint256(1) << (nonce & 255);
        require(nonceBitmap[owner][word] & mask == 0, "used");
        bytes32 digest = keccak256(abi.encode(owner, recipient, amount, nonce));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        nonceBitmap[owner][word] |= mask;
    }
}
