// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GaslessTransferSafePrincipalNonce01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public transferred;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function transferBySig(address from, address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[from], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(from, to, amount, nonce));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        nonces[from] = nonce + 1;

        transferred[to] += amount;
    }
}
