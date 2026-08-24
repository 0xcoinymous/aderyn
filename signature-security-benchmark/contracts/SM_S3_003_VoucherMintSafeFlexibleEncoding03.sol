// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_VoucherMintSafeFlexibleEncoding03 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function mintVoucher(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        uint256 nonce=nonces[actor];
        bytes32 digest=keccak256(abi.encode(actor,recipient,amount,actionId,nonce,address(this)));
        require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); nonces[actor]=nonce+1;
        spent[actor] += amount;
        aggregate += amount;
    }
}
