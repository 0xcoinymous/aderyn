// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

abstract contract SM_SM_V1_030_Base {
    function _rawRecover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(digest, v, r, s);
    }
}

contract SM_SubscriptionHighSAccept30 is SM_SM_V1_030_Base {
    address public immutable authorizedSigner;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;
    uint256 public parityCounter;
    constructor(address signer_) { authorizedSigner = signer_; }
    function chargeBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(_rawRecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
        parityCounter += amount & 1;
    }
}
