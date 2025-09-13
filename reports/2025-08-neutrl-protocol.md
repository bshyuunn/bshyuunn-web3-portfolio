# Neutrl Protocol - Findings Report

# Table of contents
- ## Medium Risk Findings
    - ### [M-01. FULL_RESTRICTED user can stake on behalf of others](#M-01)


<br>

# Medium Risk Findings

## <a id='M-01'></a>M-01. FULL_RESTRICTED user can stake on behalf of others

### Summary

The missing check on the `caller` in the [_deposit](https://github.com/sherlock-audit/2025-08-neutrl-protocol-bshyuunn/blob/64cdc3f8d4cd3f41dfb74928dcb5e3ff264261bd/contracts/src/sNUSD.sol#L337) function will cause a violation of the intended staking restriction for `FULL_RESTRICTED` users, as a `FULL_RESTRICTED` user can stake NUSD and mint sNUSD to any other address by setting the `receiver` to a non-restricted address.

Note: Due to the internal `_update` function, a `FULL_RESTRICTED` user cannot mint sNUSD to themselves (i.e., cannot receive sNUSD directly), but they can still stake on behalf of others, which violates the intended restriction.

### Root Cause

**In contracts/src/sNUSD.sol, the [_deposit](https://github.com/sherlock-audit/2025-08-neutrl-protocol-bshyuunn/blob/64cdc3f8d4cd3f41dfb74928dcb5e3ff264261bd/contracts/src/sNUSD.sol#L337) function does not check if the caller has `FULL_RESTRICTED_STAKER_ROLE`.**

```solidity
function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
    if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
        revert OperationNotAllowed();
    }
    if (assets == 0 || shares == 0) revert ZeroInput();
@>  super._deposit(caller, receiver, assets, shares);
    _checkMinShares();
}
```

### Internal Pre-conditions

- Admin grants `FULL_RESTRICTED_STAKER_ROLE` to a user (attacker).

### External Pre-conditions

1. None

### Attack Path

1. **FULL_RESTRICTED user calls deposit() or mint() with receiver set to any non-restricted address.**
2. The transaction succeeds, and sNUSD is minted to the receiver.

### Impact

The `FULL_RESTRICTED` user cannot stake for themselves, but can still stake for others, violating the intended restriction that `FULL_RESTRICTED` users "cannot stake".

This is explicitly stated in the [README](https://github.com/sherlock-audit/2025-08-neutrl-protocol-bshyuunn/blob/64cdc3f8d4cd3f41dfb74928dcb5e3ff264261bd/README.md?plain=1#L102):

> 7. Role Consistency
Property: FULL_RESTRICTED users cannot transfer and stake/unstake, SOFT_RESTRICTED cannot stake
> 

### Mitigation

```diff
function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
    if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
        revert OperationNotAllowed();
    }
+   if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller)) {
+		    revert OperationNotAllowed();
+		}
    if (assets == 0 || shares == 0) revert ZeroInput();
    super._deposit(caller, receiver, assets, shares);
    _checkMinShares();
}
```