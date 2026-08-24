// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_PermitLikeNoOneTimeAuthorizationId25 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address wallet_) { wallet = wallet_; }

    function permitLike(address owner, address spender, uint256 value, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(owner, spender, value, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        allowance[owner][spender] = value;
    }
}
