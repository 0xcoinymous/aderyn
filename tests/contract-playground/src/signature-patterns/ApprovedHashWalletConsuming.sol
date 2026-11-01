// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: the same wallet passes consumeHash = true, so isValidSignature changes state.
contract ApprovedHashWalletConsuming {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;
    mapping(address => bool) public owners;
    mapping(address => mapping(bytes32 => uint256)) public approvedHashes;

    function checkSignatures(bytes32 dataHash, bytes memory signatures, bool consumeHash) internal {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signatures, 0x20))
            s := mload(add(signatures, 0x40))
            v := byte(0, mload(add(signatures, 0x60)))
        }
        address currentOwner = address(uint160(uint256(r)));
        if (v == 1) {
            require(approvedHashes[currentOwner][dataHash] != 0, "not approved");
            if (consumeHash) {
                approvedHashes[currentOwner][dataHash] = 0;
            }
        } else {
            currentOwner = ecrecover(dataHash, v, r, s);
        }
        require(owners[currentOwner], "owner");
    }

    function isValidSignature(bytes calldata _data, bytes calldata _signature) external returns (bytes4) {
        checkSignatures(keccak256(_data), _signature, true);
        return EIP1271_MAGIC_VALUE;
    }
}
