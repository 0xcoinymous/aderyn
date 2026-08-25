// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

interface E712_IDomainProvider {
    function domainSeparator() external view returns (bytes32);
}

library E712_BenchLib {
    uint256 internal constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function recoverChecked(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        require(uint256(s) <= HALF_ORDER, "high-s");
        require(v == 27 || v == 28, "bad-v");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "zero-signer");
        return signer;
    }

    function domain(string memory name, string memory version, address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, verifyingContract));
    }

    function typedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
