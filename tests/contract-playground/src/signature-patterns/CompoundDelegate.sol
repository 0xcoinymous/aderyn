// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: Compound-style delegateBySig and permit. The domain separator is a local variable named
// domainSeparator, and the nonce is kept per recovered signer (nonce == nonces[signatory]++).
contract CompoundDelegate {
    string public constant name = "T";
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping (address => uint) public nonces;
    mapping (address => address) public delegates;
    mapping (address => mapping (address => uint96)) internal allowances;
    function delegateBySig(address delegatee, uint nonce, uint expiry, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "invalid signature");
        require(nonce == nonces[signatory]++, "invalid nonce");
        require(block.timestamp <= expiry, "signature expired");
        return _delegate(signatory, delegatee);
    }
    function permit(address owner, address spender, uint rawAmount, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        uint96 amount = uint96(rawAmount);
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, rawAmount, nonces[owner]++, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "invalid signature");
        require(signatory == owner, "unauthorized");
        require(block.timestamp <= deadline, "signature expired");
        allowances[owner][spender] = amount;
    }
    function _delegate(address delegator, address delegatee) internal { delegates[delegator] = delegatee; }
    function getChainId() internal view returns (uint) { uint256 chainId; assembly { chainId := chainid() } return chainId; }
}
