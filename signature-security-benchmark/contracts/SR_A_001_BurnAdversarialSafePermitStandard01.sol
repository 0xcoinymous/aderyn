// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BurnAdversarialSafePermitStandard01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public nonces; mapping(address => mapping(address => uint256)) public allowance;

    constructor(address signer_) { authorizedSigner = signer_; }

    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");
        uint256 nonce = nonces[owner];
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, owner, spender, value, nonce, deadline));
        require(_verifySignature(digest, signature), "invalid signature");
        nonces[owner] = nonce + 1;
        allowance[owner][spender] = value;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
