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
