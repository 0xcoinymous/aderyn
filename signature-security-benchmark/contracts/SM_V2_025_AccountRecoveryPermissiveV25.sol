// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_AccountRecoveryPermissiveV25 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    mapping(address => mapping(bytes32 => uint256)) public perActorAction;
    constructor(address signer_) { authorizedSigner = signer_; }

    function recoverAccount(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        if (v < 27) v += 27;
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        spent[actor] += amount;
        aggregate += amount;
        perActorAction[actor][actionId] += 1;
    }
}
