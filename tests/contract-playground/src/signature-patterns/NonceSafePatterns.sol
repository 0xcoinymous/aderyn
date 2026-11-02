// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe nonce patterns that must not be reported; one contract per pattern.

// A used-nonce map keyed by a struct field, verified in a helper; changing the owner is configuration.
contract StructNonceMint {
    struct Sign { uint8 v; bytes32 r; bytes32 s; uint256 nonce; }
    address public owner;
    mapping(uint256 => bool) public usedNonce;
    mapping(address => uint256) public minted;
    constructor() { owner = msg.sender; }
    function verifySign(address caller, Sign memory sign) internal view {
        bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid, caller, sign.nonce));
        require(owner == ecrecover(hash, sign.v, sign.r, sign.s), "sign");
    }
    function mint(Sign memory sign) external {
        require(!usedNonce[sign.nonce], "nonce");
        usedNonce[sign.nonce] = true;
        verifySign(msg.sender, sign);
        minted[msg.sender] += 1;
    }
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "owner");
        owner = newOwner;
    }
}

// Aave-style permit: the nonce is read into a local, signed and advanced as `local + 1`, also in a
// second signed function.
contract LocalCopyPermit {
    mapping(address => uint256) internal _nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public deposits;
    function permit(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        uint256 currentValidNonce = _nonces[owner];
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, owner, spender, value, currentValidNonce));
        require(owner == ecrecover(digest, v, r, s), "sig");
        _nonces[owner] = currentValidNonce + 1;
        allowance[owner][spender] = value;
    }
    function metaDeposit(address depositor, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        uint256 currentValidNonce = _nonces[depositor];
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, depositor, value, currentValidNonce));
        require(depositor == ecrecover(digest, v, r, s), "sig");
        _nonces[depositor] = currentValidNonce + 1;
        deposits[depositor] += value;
    }
}

// The nonce is advanced inside the `if` that checks it; a balance spent here is also spent elsewhere.
contract IfGuardedDebit {
    struct Wallet { uint256 balance; uint64 debitNonce; address owner; }
    mapping(bytes32 => Wallet) private wallets;
    uint256 public escrow;
    function debit(bytes32 walletID, uint256 value, uint64 nonce, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(keccak256(abi.encode(address(this), block.chainid, walletID, value, nonce)), v, r, s);
        Wallet storage wallet = wallets[walletID];
        if (wallet.debitNonce < nonce && wallet.balance >= value && wallet.owner == signer) {
            wallet.debitNonce = nonce;
            wallet.balance -= value;
            escrow += value;
        }
    }
    function withdraw(bytes32 walletID, uint256 value) external {
        Wallet storage wallet = wallets[walletID];
        require(wallet.owner == msg.sender, "owner");
        wallet.balance -= value;
    }
}

// Signature split into locals declared without a value; a frozen-account check is configuration.
contract GaslessTransfer {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isFrozen;
    function transferGasless(address sender, address recipient, uint256 amount, uint32 nonce, bytes memory signature) external {
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid, sender, recipient, amount, nonce));
        require(signature.length == 65, "length");
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) {
            v += 27;
        }
        address signer = ecrecover(hash, v, r, s);
        require(signer == sender, "sender");
        require(nonces[signer]++ == nonce, "nonce");
        require(!isFrozen[sender] || recipient == address(this), "frozen");
        balances[sender] -= amount;
        balances[recipient] += amount;
    }
}

// The signed message hash itself is marked used; msg.sender is part of the signed message.
contract UsedMessageHash {
    address public operationAddress;
    mapping(bytes32 => bool) public signHash;
    mapping(address => uint256) public earned;
    function recoverSigner(bytes32 message, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(message, v, r, s);
    }
    function userTakeEarn(uint256 value, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid, msg.sender, value, nonce));
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address signer = recoverSigner(messageHash, v, r, s);
        require(signer == operationAddress, "signer");
        require(signHash[messageHash] == false, "used");
        signHash[messageHash] = true;
        earned[msg.sender] += value;
    }
}

// The caller must be the signed recipient, so a nonce kept per caller is kept per signed account.
contract RecipientBoundNonce {
    address public oracle;
    mapping(address => uint256) public walletNonce;
    mapping(address => uint256) public balances;
    function mintSigned(address recipient, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(recipient == msg.sender, "sender");
        bytes32 message = keccak256(abi.encodePacked(recipient, amount, nonce, address(this), block.chainid));
        require(ecrecover(message, v, r, s) == oracle && walletNonce[msg.sender] < nonce, "sign");
        walletNonce[msg.sender] = nonce;
        balances[recipient] += amount;
    }
}

// A cancellation only marks the signed order cancelled; filling checks the mark.
contract CancelOnly {
    mapping(bytes32 => bool) public cancelledOrFinalized;
    mapping(address => uint256) public filled;
    function hashOrder(address maker, uint256 amount, uint256 salt) public view returns (bytes32) {
        return keccak256(abi.encode(address(this), block.chainid, maker, amount, salt));
    }
    function cancelOrder(address maker, uint256 amount, uint256 salt, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = hashOrder(maker, amount, salt);
        require(ecrecover(hash, v, r, s) == maker && msg.sender == maker, "maker");
        cancelledOrFinalized[hash] = true;
    }
    function fill(address maker, uint256 amount, uint256 salt, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = hashOrder(maker, amount, salt);
        require(ecrecover(hash, v, r, s) == maker, "maker");
        require(!cancelledOrFinalized[hash], "done");
        cancelledOrFinalized[hash] = true;
        filled[msg.sender] += amount;
    }
}

// Two owners sign one message that holds the nonce, built by nested helpers; the nonce advances once.
contract TwoOfThreeWallet {
    uint256 public spendNonce;
    mapping(address => bool) public owners;
    function messageToSign(address destination, uint256 value) public view returns (bytes32) {
        return keccak256(abi.encodePacked(spendNonce, address(this), block.chainid, value, destination));
    }
    function messageToRecover(address destination, uint256 value) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageToSign(destination, value)));
    }
    function validSignatures(address destination, uint256 value, uint8 v1, bytes32 r1, bytes32 s1, uint8 v2, bytes32 r2, bytes32 s2) private view returns (bool) {
        bytes32 message = messageToRecover(destination, value);
        address addr1 = ecrecover(message, v1, r1, s1);
        address addr2 = ecrecover(message, v2, r2, s2);
        return addr1 != addr2 && owners[addr1] && owners[addr2];
    }
    function spend(address payable destination, uint256 value, uint8 v1, bytes32 r1, bytes32 s1, uint8 v2, bytes32 r2, bytes32 s2) external {
        require(validSignatures(destination, value, v1, r1, s1, v2, r2, s2), "sigs");
        spendNonce = spendNonce + 1;
        destination.transfer(value);
    }
}

// The signed nonce must be one past the stored one and is stored.
contract NextNoncePreSigned {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;
    function transferPreSigned(address to, uint256 value, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid, to, value, nonce));
        address from = ecrecover(hash, v, r, s);
        require(from != address(0), "sig");
        require(nonce == nonces[from] + 1, "nonce");
        nonces[from] = nonce;
        balances[from] -= value;
        balances[to] += value;
    }
}

// A signed token id can be minted once; the request is a memory struct.
contract MintOnceRequest {
    struct Request { uint256 tokenId; address owner; bytes signature; }
    address public signerAddress;
    mapping(uint256 => address) private _owners;
    function _exists(uint256 tokenId) internal view returns (bool) {
        return _owners[tokenId] != address(0);
    }
    function _mint(address to, uint256 tokenId) internal {
        _owners[tokenId] = to;
    }
    function _safeMint(address to, uint256 tokenId) internal {
        _mint(to, tokenId);
    }
    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
    function mintTokens(Request[] calldata requests) external {
        for (uint256 i = 0; i < requests.length; i++) {
            Request memory request = requests[i];
            require(_exists(request.tokenId) == false, "exists");
            require(request.owner == msg.sender, "owner");
            bytes32 hash = keccak256(abi.encode(request.tokenId, request.owner, address(this), block.chainid));
            require(recoverSigner(hash, request.signature) == signerAddress, "sig");
            _safeMint(msg.sender, request.tokenId);
        }
    }
}

// The hash is wrapped in place before recovery; the signed id is marked used, after an assembly split.
contract WrappedHashClaim {
    address public validator;
    mapping(bytes32 => bool) public processed;
    mapping(address => uint256) public claimed;
    function toEthSigned(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function claim(bytes32 id, uint256 amount, bytes memory signature) external {
        require(signature.length == 65, "length");
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        bytes32 hash = keccak256(abi.encodePacked(id, msg.sender, amount, address(this), block.chainid));
        hash = toEthSigned(hash);
        require(ecrecover(hash, v, r, s) == validator, "sig");
        _consume(id);
        claimed[msg.sender] += amount;
    }
    function _consume(bytes32 id) internal {
        if (!processed[id]) {
            processed[id] = true;
        } else {
            revert("done");
        }
    }
}

// A signed delegation that the user can revoke; the signature count in the digest still advances.
contract RevocableDelegation {
    mapping(address => uint256) public signatureCount;
    mapping(address => mapping(address => bool)) public delegated;
    function addDelegateBySignature(address user, address delegate, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, user, delegate, signatureCount[user]++));
        require(ecrecover(digest, v, r, s) == user, "sig");
        require(!delegated[user][delegate], "delegated");
        delegated[user][delegate] = true;
    }
    function revokeDelegate(address delegate) external {
        delegated[msg.sender][delegate] = false;
    }
}

// A view helper verifies a signed order with its nonce; the state-changing caller consumes it.
contract ViewOrderCheck {
    mapping(address => mapping(bytes32 => uint256)) public filled;
    function available(address maker, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) public view returns (uint256) {
        bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid, maker, amount, nonce));
        if (ecrecover(hash, v, r, s) != maker) {
            return 0;
        }
        return amount - filled[maker][hash];
    }
}

// A signed cancellation marks the authorization cancelled with an enum value.
contract EnumCancellation {
    enum State { Unused, Used, Canceled }
    mapping(address => mapping(bytes32 => State)) public states;
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(states[authorizer][nonce] == State.Unused, "used");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, authorizer, nonce));
        require(ecrecover(digest, v, r, s) == authorizer, "sig");
        states[authorizer][nonce] = State.Canceled;
    }
}
