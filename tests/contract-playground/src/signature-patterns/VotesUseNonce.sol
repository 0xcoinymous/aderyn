// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: OpenZeppelin ERC20Votes style, `require(nonce == _useNonce(signer))` with a counter library.
library Counters {
    struct Counter { uint256 _value; }
    function current(Counter storage counter) internal view returns (uint256) { return counter._value; }
    function increment(Counter storage counter) internal { counter._value += 1; }
}

contract VotesUseNonce {
    using Counters for Counters.Counter;
    mapping(address => Counters.Counter) private _nonces;
    mapping(address => address) public delegates;

    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= expiry, "expired");
        address signer = ecrecover(keccak256(abi.encode(delegatee, nonce, expiry, address(this), block.chainid)), v, r, s);
        require(signer != address(0), "bad sig");
        require(nonce == _useNonce(signer), "invalid nonce");
        delegates[signer] = delegatee;
    }

    function _useNonce(address owner) internal returns (uint256 current) {
        Counters.Counter storage nonce = _nonces[owner];
        current = nonce.current();
        nonce.increment();
    }
}
