// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BurnSafeDomainContractChain03 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => uint256) public burned;
    mapping(address => uint256) public nonces;

    constructor(address wallet_) { wallet = wallet_; }

    function burnBySig(address holder, uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[holder], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(holder, amount, address(this), block.chainid, nonce));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        nonces[holder] = nonce + 1;

        burned[holder] += amount;
    }
}
