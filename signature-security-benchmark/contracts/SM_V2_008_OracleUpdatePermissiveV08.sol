// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_OracleUpdatePermissiveV08 {
    address public immutable authorizedSigner;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address signer_) { authorizedSigner = signer_; }

    function updateBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) && v < 2) recovered = ecrecover(digest, v + 27, r, s);
        require(recovered == authorizedSigner, "invalid signature");
        allowance[actor][recipient] = amount;
    }
}
