// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: a lazy mint validates each creator's signature with ERC-1271 for contracts and ECDSA otherwise,
// comparing the answer exactly; another function only has a local variable called `signer`.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

contract CreatorSignatureCaller {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    mapping(uint256 => address) public creatorOf;
    mapping(address => uint256) public claimed;

    function validate(address signer, bytes32 hash, bytes memory signature) internal view {
        if (signer.code.length == 0) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            require(ecrecover(hash, v, r, s) == signer, "signature");
        } else {
            require(IERC1271(signer).isValidSignature(hash, signature) == MAGICVALUE, "contract signature");
        }
    }

    function mintAndTransfer(uint256 tokenId, address creator, bytes memory signature, address to) external {
        require(creatorOf[tokenId] == address(0), "minted");
        bytes32 hash = keccak256(abi.encode(address(this), block.chainid, tokenId, creator, to));
        validate(creator, hash, signature);
        creatorOf[tokenId] = creator;
    }

    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(keccak256(abi.encode(address(this), msg.sender, amount)), v, r, s);
        require(signer == creatorOf[amount], "creator");
        claimed[msg.sender] += amount;
    }
}
