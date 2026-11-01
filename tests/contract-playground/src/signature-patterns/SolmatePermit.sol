// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: solmate permit, nonce advanced inside the signed digest within an unchecked block.
contract SolmatePermit {
    string public name = "T";
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 internal immutable INITIAL_CHAIN_ID;
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;
    constructor() { INITIAL_CHAIN_ID = block.chainid; INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator(); }
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual {
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        owner, spender, value, nonces[owner]++, deadline)))),
                v, r, s);
            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");
            allowance[recoveredAddress][spender] = value;
        }
    }
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();
    }
    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)), keccak256("1"), block.chainid, address(this)));
    }
}
