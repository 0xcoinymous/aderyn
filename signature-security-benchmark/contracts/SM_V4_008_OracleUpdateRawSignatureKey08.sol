// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_OracleUpdateRawSignatureKey08 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    constructor(address signer_) { authorizedSigner = signer_; }

    function updateBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(signature);
        require(!consumedSignature[key], "signature used");
        address recovered = SM_MalleabilityBenchLib.recoverRaw(digest,v,r,s); require(recovered==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        cumulative[actionId] += amount;
        participant[actor] = true;
    }
}
