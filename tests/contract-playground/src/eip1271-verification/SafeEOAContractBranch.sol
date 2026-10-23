// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe consumer (OpenZeppelin SignatureChecker style): ECDSA for EOAs, exact ERC-1271 check for contracts.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract SafeEOAContractBranch {
    uint256 public accepted;
    mapping(address => bool) public approved;

    function _recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }

    function _isValid(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length == 0) {
            address recovered = _recover(hash, signature);
            return recovered != address(0) && recovered == signer;
        }
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function approve(address signer, bytes32 hash, bytes calldata signature) external {
        require(_isValid(signer, hash, signature), "invalid");
        approved[signer] = true;
        accepted += 1;
    }
}
