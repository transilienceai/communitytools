# Blockchain Security Skill

Smart contract vulnerability analysis and exploitation for CTF challenges and security assessments.

## When to Use
- Analyzing Solidity smart contracts for vulnerabilities
- Solving blockchain CTF challenges (HTB, Ethernaut, Damn Vulnerable DeFi)
- Testing delegatecall, reentrancy, access control, storage manipulation
- Predicting CREATE/CREATE2 contract addresses

## Key Capabilities
- **Delegatecall storage attacks**: Mirror storage layout, write to victim's slots
- **CREATE address prediction**: Brute-force nonces to deploy at target addresses
- **Storage slot computation**: Read private variables, compute mapping slots
- **EVM bytecode crafting**: Deploy minimal exploit contracts without Solidity

## Tools Required
- `web3.py` (pip install web3)
- `solcx` (pip install py-solc-x) for Solidity compilation
- `rlp` (pip install rlp) for address computation
- Alternatively: `cast`/`forge` from Foundry

## Files
- `SKILL.md` - Attack vectors, tool usage, quick reference
- `reference/delegatecall-attacks.md` - Delegatecall exploitation patterns
- `reference/create-address-prediction.md` - Nonce brute-force and address prediction
- `reference/storage-layout.md` - Solidity storage slot computation
