// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

library SR_ReplayBenchECDSA {
    function recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        signer = ecrecover(digest, v, r, s);
    }

    function tryRecover(bytes32 digest, bytes calldata signature) internal pure returns (address signer, bool ok) {
        signer = recover(digest, signature);
        ok = signer != address(0);
    }
}

interface SR_IReplayBenchVerifier {
    function isValid(address signer, bytes32 digest, bytes calldata signature) external view returns (bool);
}

interface SR_IReplayBench1271 {
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}

interface SR_IReplayBenchAction {
    function run(bytes calldata payload) external returns (bool);
}

library SR_ReplayBenchSignatureChecker {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    function isValidSignatureNow(address signer, bytes32 digest, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signer.code.length == 0) {
            return SR_ReplayBenchECDSA.recover(digest, signature) == signer;
        }
        (bool success, bytes memory data) = signer.staticcall(
            abi.encodeWithSelector(SR_IReplayBench1271.isValidSignature.selector, digest, signature)
        );
        return success && data.length >= 32 && abi.decode(data, (bytes4)) == MAGICVALUE;
    }
}

abstract contract SR_ReplayBenchSignerBase {
    address public immutable authorizedSigner;

    constructor(address signer_) {
        authorizedSigner = signer_;
    }

    function _isAuthorized(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
