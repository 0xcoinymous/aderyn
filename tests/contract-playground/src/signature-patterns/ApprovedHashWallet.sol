// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Gnosis Safe 1.1 style: isValidSignature calls checkSignatures with consumeHash = false, so the write that
// frees an approved hash cannot run; the loop counter is a local declared without a value. Safe.
contract ApprovedHashWallet {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;
    uint256 public threshold;
    mapping(address => bool) public owners;
    mapping(address => mapping(bytes32 => uint256)) public approvedHashes;

    function checkSignatures(bytes32 dataHash, bytes memory signatures, bool consumeHash) internal {
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;
        for (i = 0; i < threshold; i++) {
            assembly {
                let pos := mul(0x41, i)
                r := mload(add(signatures, add(pos, 0x20)))
                s := mload(add(signatures, add(pos, 0x40)))
                v := and(mload(add(signatures, add(pos, 0x41))), 0xff)
            }
            if (v == 1) {
                currentOwner = address(uint160(uint256(r)));
                require(msg.sender == currentOwner || approvedHashes[currentOwner][dataHash] != 0, "not approved");
                if (consumeHash && msg.sender != currentOwner) {
                    approvedHashes[currentOwner][dataHash] = 0;
                }
            } else {
                currentOwner = ecrecover(dataHash, v, r, s);
            }
            require(currentOwner > lastOwner && owners[currentOwner], "owner");
            lastOwner = currentOwner;
        }
    }

    function isValidSignature(bytes calldata _data, bytes calldata _signature) external returns (bytes4) {
        checkSignatures(keccak256(_data), _signature, false);
        return EIP1271_MAGIC_VALUE;
    }
}
