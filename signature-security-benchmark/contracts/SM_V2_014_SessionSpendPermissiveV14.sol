// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SessionSpendPermissiveV14 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public totals;

    constructor(address signer_) { authorizedSigner = signer_; }

    function spendBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        v = v == 0 ? 27 : 28;
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        totals[actionId] = totals[actionId] + amount;
    }
}
