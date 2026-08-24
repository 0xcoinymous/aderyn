// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_GovernanceVotePermissiveV07 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;

    constructor(address signer_) { authorizedSigner = signer_; }

    function voteBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        uint8 parity = uint8(uint256(v) & 1);
        address recovered = ecrecover(digest, parity + 27, r, s);
        require(recovered == authorizedSigner, "invalid signature");
        completed[actionId] = true;
        completionCount += 1;
    }
}
