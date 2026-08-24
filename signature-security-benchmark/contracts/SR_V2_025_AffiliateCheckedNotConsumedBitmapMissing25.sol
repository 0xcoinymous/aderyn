// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AffiliateCheckedNotConsumedBitmapMissing25 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public affiliateCredit;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function creditAffiliate(address affiliate, uint256 amount, bytes32 campaign, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        uint256 word = uint256(authorizationId) >> 8;
        uint256 mask = uint256(1) << (uint256(authorizationId) & 255);
        require(nonceBitmap[affiliate][word] & mask == 0, "used");

        bytes32 digest = keccak256(abi.encode(affiliate, amount, campaign, authorizationId));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        affiliateCredit[affiliate] += amount;
    }
}
