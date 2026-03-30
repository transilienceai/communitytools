---
name: blockchain-security
description: Smart contract security testing and blockchain CTF exploitation. Covers Solidity vulnerability analysis, EVM storage manipulation, delegatecall attacks, CREATE/CREATE2 address prediction, and common DeFi exploit patterns. Use when analyzing Solidity contracts, solving blockchain challenges, or testing smart contract security.
---

# Blockchain Security

## Quick Start
1. Download and decompile contracts (source or bytecode)
2. Map storage layout and identify privileged operations
3. Check for delegatecall, CREATE address prediction, reentrancy, access control
4. Deploy exploit contracts via web3.py or cast/forge
5. Verify win condition (isSolved/flag endpoint)

## HTB Blockchain Challenge Pattern
```bash
# Get connection info
curl http://$HOST:$PORT/connection_info  # -> PrivateKey, Address, TargetAddress, setupAddress
# RPC endpoint
RPC_URL="http://$HOST:$PORT/rpc"
# Win condition: Setup.isSolved() must return true
```

## Key Attack Vectors

### 1. Delegatecall Storage Manipulation
When contract A does `delegatecall` to contract B, B's code runs with A's storage.
- Deploy exploit contract that mirrors A's storage layout
- Exploit contract writes to A's storage slots via delegatecall
- **Critical**: Storage layout must match exactly (same slot ordering)
- See [reference/delegatecall-attacks.md](reference/delegatecall-attacks.md)

### 2. CREATE Address Prediction (Nonce Manipulation)
Contract addresses from CREATE are deterministic: `keccak256(rlp([sender, nonce]))[12:]`
- Brute-force nonce to find which nonce produces target address
- Send dummy transactions (self-transfers) to increment nonce
- Deploy exploit contract at the exact nonce that hits target address
- See [reference/create-address-prediction.md](reference/create-address-prediction.md)

### 3. Storage Layout & Slot Computation
- Mappings: `keccak256(h(key) || uint256(slot_number))`
  - Value types: `h(k) = abi.encode(k)` (left-padded to 32 bytes)
  - String/bytes: `h(k) = keccak256(k)`
- Read private variables via `eth_getStorageAt`
- See [reference/storage-layout.md](reference/storage-layout.md)

### 4. Common Vulnerability Classes
| Vulnerability | Check |
|---|---|
| Reentrancy | External calls before state updates |
| Access control | Missing onlyOwner / msg.sender checks |
| Integer overflow | Solidity < 0.8.0 without SafeMath |
| Delegatecall injection | User-controlled delegatecall target |
| tx.origin auth | `tx.origin` instead of `msg.sender` |
| Selfdestruct | Force-send ETH, reset contract nonce |
| Weak randomness | blockhash/timestamp as entropy source |

## Tools
```python
# web3.py essentials
from web3 import Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))
acct = w3.eth.account.from_key(PRIVATE_KEY)

# Read private storage
w3.eth.get_storage_at(contract_addr, slot)

# Deploy contract
from solcx import compile_source, install_solc
install_solc("0.8.13")
compiled = compile_source(source, output_values=["abi", "bin"], solc_version="0.8.13")

# Send raw bytecode deployment
tx = {'data': bytecode, 'gas': 3000000, 'gasPrice': w3.eth.gas_price, 'nonce': nonce, 'chainId': chain_id}
signed = acct.sign_transaction(tx)
w3.eth.send_raw_transaction(signed.raw_transaction)
```

## Reference
- [Delegatecall Attacks](reference/delegatecall-attacks.md)
- [CREATE Address Prediction](reference/create-address-prediction.md)
- [Storage Layout](reference/storage-layout.md)

## Critical Rules
- Always read storage before attacking (private vars are readable on-chain)
- Mirror exact storage layout when exploiting delegatecall
- For CREATE nonce brute-force, check nonces 0-100000+ systematically
- HTB instances are ephemeral -- script the full attack for speed
