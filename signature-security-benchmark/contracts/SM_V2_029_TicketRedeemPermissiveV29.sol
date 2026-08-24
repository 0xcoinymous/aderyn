// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_TicketRedeemPermissiveV29 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public credited;

    mapping(bytes32 => bool) public pendingFlag;
    constructor(address signer_) { authorizedSigner = signer_; }

    function redeemTicket(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        if (v >= 35) v = uint8(((uint256(v) - 35) & 1) + 27);
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        credited[recipient] += amount;
        pendingFlag[actionId] = true;
                delete pendingFlag[actionId];
    }
}
