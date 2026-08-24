// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VoucherMintNoOneTimeNone03 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public minted;

    constructor(address signer_) { authorizedSigner = signer_; }

    function mintWithVoucher(address recipient, uint256 quantity, bytes32 voucherId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(recipient, quantity, voucherId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        minted[recipient] += quantity;
    }
}
