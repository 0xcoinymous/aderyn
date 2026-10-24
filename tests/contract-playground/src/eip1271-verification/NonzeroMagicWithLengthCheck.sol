// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

// Vulnerable caller: any non-zero answer is accepted. Wallets return 0xffffffff for an invalid
// signature, so invalid signatures pass. The `ret.length == 32` comparison is not a magic check.
contract NonzeroMagicWithLengthCheck {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public used;

    function transferBySig(address wallet, address to, uint256 amount, bytes32 id, bytes calldata sig) external {
        require(!used[id], "used");
        bytes32 digest = keccak256(abi.encode(wallet, to, amount, id, address(this), block.chainid));
        require(_isValidERC1271(wallet, digest, sig), "bad signature");
        used[id] = true;
        balances[wallet] -= amount;
        balances[to] += amount;
    }

    function _isValidERC1271(address wallet, bytes32 hash, bytes memory signature) internal view returns (bool) {
        (bool ok, bytes memory ret) = wallet.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );
        return ok && ret.length == 32 && abi.decode(ret, (bytes4)) != bytes4(0);
    }
}
