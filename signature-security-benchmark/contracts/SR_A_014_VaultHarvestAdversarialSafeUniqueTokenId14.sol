// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VaultHarvestAdversarialSafeUniqueTokenId14 {
    address public immutable authorizedSigner;
    mapping(uint256 => address) public ownerOf;
    constructor(address signer_) { authorizedSigner = signer_; }
    function mint(uint256 tokenId, address recipient, bytes calldata signature) external {
        require(ownerOf[tokenId] == address(0), "already minted");
        bytes32 digest = keccak256(abi.encode(address(this), tokenId, recipient));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        ownerOf[tokenId] = recipient;
    }
}
