// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: `abi.encodePacked(uint16(0x1901), domainSeparator, structHash)` produces the bytes 0x19 0x01.
contract Uint16PrefixPermit {
    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("T")), keccak256(bytes("1")), block.chainid, address(this)));
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 hashStruct = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked(uint16(0x1901), DOMAIN_SEPARATOR(), hashStruct));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == owner, "bad sig");
        allowance[owner][spender] = value;
    }
}
