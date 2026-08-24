// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BurnNoOneTimeSignedNonce09 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public burned;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function burnBySig(address holder, uint256 amount, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(holder, amount, nonce));

        require(_isAuthorized(digest, signature), "invalid signature");

        burned[holder] += amount;
    }
}
