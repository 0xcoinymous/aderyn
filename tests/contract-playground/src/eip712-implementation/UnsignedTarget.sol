// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: only the calldata is signed; the relayer picks the call target freely.
contract UnsignedTarget {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant CALL_TYPEHASH = keccak256("Call(address signer,bytes32 dataHash,uint256 nonce)");

    mapping(address => uint256) public nonces;

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("UnsignedTarget")), keccak256(bytes("1")), block.chainid, address(this)));
    }

    function execute(address signer, address target, bytes calldata callData, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce = nonces[signer];
        bytes32 structHash = keccak256(abi.encode(CALL_TYPEHASH, signer, keccak256(callData), nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        (bool ok,) = target.call(callData);
        require(ok, "call failed");
    }
}
