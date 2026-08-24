// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_CollateralWithdrawHighSAccept23 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    bytes32 public lastContext;
    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawCollateral(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(uint256(s) < 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141, "s out of curve range");
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        cumulative[actionId] += amount;
        participant[actor] = true;
        lastContext = keccak256(abi.encode(actor, actionId));
    }
}
