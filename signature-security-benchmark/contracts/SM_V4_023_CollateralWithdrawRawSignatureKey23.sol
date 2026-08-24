// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_CollateralWithdrawRawSignatureKey23 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    bytes32 public lastContext;
    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawCollateral(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(abi.encodePacked(bytes1(v), r, s));
        require(!consumedSignature[key], "signature used");
        uint8 effectiveV = uint8((v & 1) + 27); require(ecrecover(digest,effectiveV,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
        lastContext = keccak256(abi.encode(actor, actionId));
    }
}
