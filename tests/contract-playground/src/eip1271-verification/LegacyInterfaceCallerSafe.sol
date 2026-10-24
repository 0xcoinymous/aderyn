// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISignatureValidator {
    function isValidSignature(bytes memory data, bytes memory signature) external view returns (bytes4);
}

// Safe 1.3.0-style caller of the legacy interface: the signed data (not its hash) is forwarded and the
// answer is compared exactly with the legacy magic value.
contract LegacyInterfaceCallerSafe {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;

    function checkContractSignature(
        bytes32 dataHash,
        bytes memory data,
        bytes memory signatures,
        address owner
    ) public view {
        require(dataHash == keccak256(data), "hash");
        bytes memory contractSignature = signatures;
        require(
            ISignatureValidator(owner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE,
            "invalid contract signature"
        );
    }
}
