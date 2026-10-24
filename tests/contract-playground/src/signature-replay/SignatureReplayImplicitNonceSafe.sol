// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Counters {
    struct Counter {
        uint256 _value;
    }

    function current(Counter storage counter) internal view returns (uint256) {
        return counter._value;
    }

    function increment(Counter storage counter) internal {
        counter._value += 1;
    }
}

// Nonces consumed implicitly: the current value is encoded in the signed digest and advanced in the
// same step (Uniswap V2 style, OpenZeppelin 5 style, OpenZeppelin 4 Counters style).
contract SignatureReplayImplicitNonceSafe {
    using Counters for Counters.Counter;

    address public signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) private _plainNonces;
    mapping(address => Counters.Counter) private _counterNonces;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address signer_) { signer = signer_; }

    function permitInline(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, nonces[owner]++, address(this), block.chainid)
        );
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        allowance[owner][spender] = value;
    }

    function permitHelper(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, _useNonce(owner), address(this), block.chainid)
        );
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        allowance[owner][spender] = value;
    }

    function permitCounter(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, _useCounterNonce(owner), address(this), block.chainid)
        );
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        allowance[owner][spender] = value;
    }

    function _useNonce(address owner) internal returns (uint256) {
        unchecked {
            return _plainNonces[owner]++;
        }
    }

    function _useCounterNonce(address owner) internal returns (uint256 current) {
        Counters.Counter storage nonce = _counterNonces[owner];
        current = nonce.current();
        nonce.increment();
    }
}
