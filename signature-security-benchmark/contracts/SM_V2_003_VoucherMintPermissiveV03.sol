// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_VoucherMintPermissiveV03 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    constructor(address signer_) { authorizedSigner = signer_; }

    function mintVoucher(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(uint256(s) > 0 && uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "non-canonical s");
        v = uint8((uint256(v) % 27) + 27);
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
    }
}
