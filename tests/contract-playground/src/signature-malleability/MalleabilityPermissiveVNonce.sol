// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// s is bounded, but v is normalised permissively (v = 0/1 and v = 27/28 both accepted). Replay protection
// comes from the signed nonce, so this is not exploitable; the permissive normalisation is still reported.
contract MalleabilityPermissiveVNonce {
    address public signer;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { signer = signer_; }

    function withdraw(address payable to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "s");
        if (v < 27) v += 27;
        bytes32 digest = keccak256(abi.encode(to, amount, nonces[to]++, address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        to.transfer(amount);
    }
}
