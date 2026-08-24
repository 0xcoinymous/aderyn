// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VoucherMintSafeDomainContract01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public minted;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function mintWithVoucher(address recipient, uint256 quantity, bytes32 voucherId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(recipient, quantity, voucherId, address(this), authorizationId));

        _authorize(digest, signature);

        used[authorizationId] = true;

        minted[recipient] += quantity;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
