// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BridgeReleasePermissiveV04 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        v = uint8((v & 1) + 27);
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        cumulative[actionId] += amount;
        participant[actor] = true;
    }
}
