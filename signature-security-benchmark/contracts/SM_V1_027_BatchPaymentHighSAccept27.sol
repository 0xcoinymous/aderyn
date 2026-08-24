// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BatchPaymentHighSAccept27 {
    address public immutable authorizedSigner;
    mapping(address => mapping(address => uint256)) public allowance;

    mapping(address => uint256) public cumulativeAmount;
    constructor(address signer_) { authorizedSigner = signer_; }

    function _recoverUnchecked(bytes32 d, uint8 vv, bytes32 rr, bytes32 ss) internal pure returns (address) {
        return ecrecover(d, vv, rr, ss);
    }

    function batchPayBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(_recoverUnchecked(digest, v, r, s) == authorizedSigner, "invalid signature");
        allowance[actor][recipient] = amount;
        if (amount != 0) { cumulativeAmount[actor] += amount; }
    }
}
