// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_AccountRecoveryMultiEncoding25 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    mapping(address => mapping(bytes32 => uint256)) public perActorAction;
    constructor(address signer_) { authorizedSigner = signer_; }

    function recoverAccount(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        bytes32 encodingKey = keccak256(signature);
        require(!usedEncoding[encodingKey], "used encoding");
        address recovered = SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest, signature);
        require(recovered == authorizedSigner, "invalid signature");
        usedEncoding[encodingKey] = true;
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
        perActorAction[actor][actionId] += 1;
    }
}
