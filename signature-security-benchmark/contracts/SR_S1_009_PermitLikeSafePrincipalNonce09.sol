// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_PermitLikeSafePrincipalNonce09 is SR_ReplayBenchSignerBase {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function permitLike(address owner, address spender, uint256 value, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[owner], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(owner, spender, value, nonce));

        require(_isAuthorized(digest, signature), "invalid signature");

        nonces[owner] = nonce + 1;

        allowance[owner][spender] = value;
    }
}
