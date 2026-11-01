// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: the legacy interface isValidSignature(bytes,bytes) answering with its own magic value 0x20c13b0b.
contract LegacyErc1271Wallet {
    bytes4 internal constant LEGACY_MAGIC_VALUE = 0x20c13b0b;
    address public immutable owner;

    constructor(address owner_) { owner = owner_; }

    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4) {
        require(signature.length == 65, "length");
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        address recovered = ecrecover(keccak256(abi.encodePacked(address(this), keccak256(data))), v, r, s);
        require(recovered != address(0) && recovered == owner, "bad sig");
        return LEGACY_MAGIC_VALUE;
    }
}
