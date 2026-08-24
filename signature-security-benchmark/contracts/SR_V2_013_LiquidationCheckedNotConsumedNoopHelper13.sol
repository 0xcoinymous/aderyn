// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LiquidationCheckedNotConsumedNoopHelper13 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(bytes32 => uint256) public liquidatedDebt;
    mapping(bytes32 => bool) public used;

    constructor(address wallet_) { wallet = wallet_; }

    function liquidateBySig(address account, uint256 debt, bytes32 positionId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(account, debt, positionId, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        _consume(authorizationId);

        liquidatedDebt[positionId] += debt;
    }


    function _consume(bytes32) internal pure {}
}
