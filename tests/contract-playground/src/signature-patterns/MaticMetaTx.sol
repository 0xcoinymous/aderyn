// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: Polygon NativeMetaTransaction. A failed inner call reverts the nonce update together with
// its effect, so the signature is still used at most once.
contract MaticMetaTx {
    struct MetaTransaction { uint256 nonce; address from; bytes functionSignature; }
    bytes32 private constant META_TRANSACTION_TYPEHASH = keccak256(bytes("MetaTransaction(uint256 nonce,address from,bytes functionSignature)"));
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(bytes("EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)"));
    mapping(address => uint256) nonces;
    function getDomainSeperator() public view returns (bytes32) {
        return keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256(bytes("T")), keccak256(bytes("1")), address(this), bytes32(block.chainid)));
    }
    function executeMetaTransaction(address userAddress, bytes memory functionSignature, bytes32 sigR, bytes32 sigS, uint8 sigV) public payable returns (bytes memory) {
        MetaTransaction memory metaTx = MetaTransaction({nonce: nonces[userAddress], from: userAddress, functionSignature: functionSignature});
        require(verify(userAddress, metaTx, sigR, sigS, sigV), "Signer and signature do not match");
        nonces[userAddress] = nonces[userAddress] + 1;
        (bool success, bytes memory returnData) = address(this).call(abi.encodePacked(functionSignature, userAddress));
        require(success, "Function call not successful");
        return returnData;
    }
    function hashMetaTransaction(MetaTransaction memory metaTx) internal pure returns (bytes32) {
        return keccak256(abi.encode(META_TRANSACTION_TYPEHASH, metaTx.nonce, metaTx.from, keccak256(metaTx.functionSignature)));
    }
    function toTypedMessageHash(bytes32 messageHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", getDomainSeperator(), messageHash));
    }
    function verify(address signer, MetaTransaction memory metaTx, bytes32 sigR, bytes32 sigS, uint8 sigV) internal view returns (bool) {
        require(signer != address(0), "INVALID_SIGNER");
        return signer == ecrecover(toTypedMessageHash(hashMetaTransaction(metaTx)), sigV, sigR, sigS);
    }
}
