// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_FeeRebateRawSignatureKey13 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function rebateBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = keccak256(bytes.concat(r, s, bytes1(v)));
        require(!consumedSignature[key], "signature used");
        require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        spent[actor] += amount;
        aggregate += amount;
    }
}
