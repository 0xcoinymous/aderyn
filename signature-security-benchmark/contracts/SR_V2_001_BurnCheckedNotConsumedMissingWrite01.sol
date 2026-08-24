// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BurnCheckedNotConsumedMissingWrite01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public burned;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function burnBySig(address holder, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(holder, amount, authorizationId));

        require(_verifySignature(digest, signature), "invalid signature");

        burned[holder] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
