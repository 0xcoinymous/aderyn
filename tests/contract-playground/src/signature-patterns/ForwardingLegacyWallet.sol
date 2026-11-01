// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: the bytes32 variant forwards to the bytes variant declared in an abstract base (Loopring style).
abstract contract ERC1271Base {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x20c13b0b;

    function isValidSignature(bytes memory _data, bytes memory _signature) public view virtual returns (bytes4);

    function isValidSignature(bytes32 _hash, bytes memory _signature) public view virtual returns (bytes4 magicValue) {
        return isValidSignature(abi.encodePacked(_hash), _signature);
    }
}

contract ForwardingLegacyWallet is ERC1271Base {
    mapping(address => bool) public isManager;

    function isValidSignature(bytes memory _data, bytes memory _signature) public view override returns (bytes4) {
        require(_signature.length == 65, "length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := byte(0, mload(add(_signature, 0x60)))
        }
        address signer = ecrecover(keccak256(_data), v, r, s);
        return isManager[signer] ? ERC1271_MAGICVALUE : bytes4(0);
    }
}
