// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library SigLib {
    function recoverChecked(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "s");
        require(v == 27 || v == 28, "v");
        address recovered = ecrecover(hash, v, r, s);
        require(recovered != address(0), "zero");
        return recovered;
    }
}

// Correct sequential nonce; the library call and the hex literal of the s bound are not storage slots.
contract NonceLibraryRecoverSafe {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    function claim(address account, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[account], "nonce");
        bytes32 digest = keccak256(abi.encode(account, amount, nonce, address(this), block.chainid));
        require(SigLib.recoverChecked(digest, v, r, s) == account, "sig");
        nonces[account] = nonce + 1;
        credits[account] += amount;
    }
}
