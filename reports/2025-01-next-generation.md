# Next Generation - Findings Report

# Table of contents
- ## High Risk Findings
    - ### [H-01. Insecure domainSeparator Usage](#H-01)
- ## Medium Risk Findings
    - ### [M-01. Missing Deadline and minGasLessFee Check in Forwarder Contract](#M-01)
- ## Low Risk Findings
    - ### [L-01. Missing Zero Address Validation in transferWithAuthorization](#L-01)


<br>

# High Risk Findings

## <a id='H-01'></a>H-01. Missing Zero Address Validation in transferWithAuthorization            

### Finding description and impact

When [`execute()`](https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L93) is called, the user directly provides the domainSeparator. This value is supposed to ensure that signed data remains valid only within a specific context. However, since it is supplied by the user, several issues arise:

```solidity
function execute(
    ForwardRequest calldata req,
@>  bytes32 domainSeparator,
    bytes32 requestTypeHash,
    bytes calldata suffixData,
    bytes calldata sig
) external payable returns (bool success, bytes memory ret) {
    _verifyNonce(req);
    _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
    _updateNonce(req);

    require(req.to == _eurfAddress, "NGEUR Forwarder: can only forward NGEUR transactions");

    bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 reqTransferSelector = bytes4(req.data[:4]);

    require(reqTransferSelector == transferSelector, "NGEUR Forwarder: can only forward transfer transactions");

    // solhint-disable-next-line avoid-low-level-calls
    (success, ret) = req.to.call{gas: req.gas, value: req.value}(abi.encodePacked(req.data, req.from));
    require(success, "NGEUR Forwarder: failed tx execution");

    _eurf.payGaslessBasefee(req.from, _msgSender());

    return (success, ret);
}
```

1. **Cross-Chain Reusability**
    
    Because there is no chain ID validation, the same signed data could potentially be reused on a different chain.
    
2. **Reusability Across Services**
    
    If another service uses a similar requestType signature, attackers could reuse the exact signed bytes from that service for unauthorized transactions.
    

### Recommended mitigation steps

Implement the Forwarder to meet EIP-712 requirements.

<br>

# Medium Risk Findings

## <a id='M-01'></a>M-01. Missing Zero Address Validation in transferWithAuthorization

### Finding description and impact

The [`execute`](https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/Forwarder.sol#L93) function in the Forwarder Contract does not include a deadline check. As a result, a message signed by a user for a transfer can be executed later than expected, causing potential confusion for users.

```solidity
struct ForwardRequest {
    address from;
    address to;
    uint256 value;
    uint256 gas;
    uint256 nonce;
    bytes data;
}

function execute(
    ForwardRequest calldata req,
    bytes32 domainSeparator,
    bytes32 requestTypeHash,
    bytes calldata suffixData,
    bytes calldata sig
) external payable returns (bool success, bytes memory ret) {
    _verifyNonce(req);
    _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
    _updateNonce(req);

    require(req.to == _eurfAddress, "NGEUR Forwarder: can only forward NGEUR transactions");

    bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 reqTransferSelector = bytes4(req.data[:4]);

    require(reqTransferSelector == transferSelector, "NGEUR Forwarder: can only forward transfer transactions");

    // solhint-disable-next-line avoid-low-level-calls
    (success, ret) = req.to.call{gas: req.gas, value: req.value}(abi.encodePacked(req.data, req.from));
    require(success, "NGEUR Forwarder: failed tx execution");

    _eurf.payGaslessBasefee(req.from, _msgSender());

    return (success, ret);
}
```

Without a deadline parameter, the signed message can be executed after a long delay, which might not be the user’s original intent.

In addition, the GaslessBasefee is a value that changes frequently based on the network's fee values. If the user fails to specify a minimum value for this fee, for example, they may be charged more GaslessBasefee than expected. This issue can be mitigated somewhat by adding a deadline check.

### Recommended mitigation steps

It is recommended to add a deadline parameter and revert the transaction if the current block timestamp exceeds this deadline. Below is an example of how this can be implemented:

```diff
struct ForwardRequest {
    address from;
    address to;
    uint256 value;
+   uint256 deadline    
    uint256 gas;
    uint256 nonce;
    bytes data;
}

function execute(
    ForwardRequest calldata req,
    bytes32 domainSeparator,
    bytes32 requestTypeHash,
    bytes calldata suffixData,
    bytes calldata sig
) external payable returns (bool success, bytes memory ret) {
    _verifyNonce(req);
    _verifySig(req, domainSeparator, requestTypeHash, suffixData, sig);
    _updateNonce(req);

+		if (block.timestamp > req.deadline) revert();
    require(req.to == _eurfAddress, "NGEUR Forwarder: can only forward NGEUR transactions");

    bytes4 transferSelector = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 reqTransferSelector = bytes4(req.data[:4]);

    require(reqTransferSelector == transferSelector, "NGEUR Forwarder: can only forward transfer transactions");

    // solhint-disable-next-line avoid-low-level-calls
    (success, ret) = req.to.call{gas: req.gas, value: req.value}(abi.encodePacked(req.data, req.from));
    require(success, "NGEUR Forwarder: failed tx execution");

    _eurf.payGaslessBasefee(req.from, _msgSender());

    return (success, ret);
}

```

<br>

# Low Risk Findings

## <a id='H-01'></a>H-01. Missing Override for Approve and Permit in RToken            

### Finding description and impact

In the [`transferWithAuthorization`](https://github.com/code-423n4/2025-01-next-generation/blob/499cfa50a56126c0c3c6caa30808d79f82d31e34/contracts/ERC20MetaTxUpgradeable.sol#L72) function, the contract performs the token transfer using `_update` directly, without checking if spender is the zero address. Because of this omission, a user can transfer tokens to the 0x0 address, effectively burning them and reducing the total supply arbitrarily.

```solidity
/**
 * @dev transferWithAuthorization function transferWithAuthorization if valid signed twa is provided.
 */
function transferWithAuthorization(
    address holder,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
) public virtual returns (bool) {
    if (block.timestamp > deadline) revert DeadLineExpired(deadline);

    bytes32 structHash = keccak256(abi.encode(_TWA_TYPEHASH, holder, spender, value, _useNonce(holder), deadline));

    bytes32 hash = _hashTypedDataV4(structHash);

    address signer = ECDSA.recover(hash, v, r, s);
    if (signer != holder) revert InvalidSignature();

@>  _update(holder, spender, value);

    return true;
}
```

### Proof of Concept

In the `test_poc_user_can_burn_token` test function below, you can see that `totalSupply` decreased from 400000000 to 390000000 after the `transferWithAuthorization` function call.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {EURFToken} from "src/Token.sol";
import {ERC20ControlerMinterUpgradeable} from "src/ERC20ControlerMinterUpgradeable.sol";
import {FeesHandlerUpgradeable} from "src/FeesHandlerUpgradeable.sol";

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {TestEURFToken} from "test/TestEURFToken.t.sol";

contract TestMetaTx is TestEURFToken {
    function setUp() public override {
        super.setUp();
    }

    function test_poc_user_can_burn_token() public {
        address holder = vm.addr(0x1);

        // 1. Mint 100 EURF tokens to the holder
        vm.prank(masterMinter);
        proxyEURFToken.mint(holder, 100e6);
        assertEq(proxyEURFToken.balanceOf(holder), 100e6);
        
        // 2. Check totalSupply
        uint256 beforeTotalSupply = proxyEURFToken.totalSupply();
        console.log("proxyEURFToken.totalSupply(): ", proxyEURFToken.totalSupply());
        // proxyEURFToken.totalSupply():  400000000

        // 3. holder transfer 10 EURF tokens to address(0x0)
        // Since there is no check on the spender, it is possible to send the token with 0x0, resulting in the token being burned
        uint256 holderPrivateKey = 0x1;
        address spender = address(0x0);
        uint256 value = 10e6;
        uint256 nonce = proxyEURFToken.nonce(holder);
        uint256 deadline = block.timestamp + 1000;

        bytes32 hash = keccak256(
            abi.encodePacked(
                hex"1901",
                proxyEURFToken.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256(
                            "TransferWithAuthorization(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                        ),
                        holder,
                        spender,
                        value,
                        nonce,
                        deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(holderPrivateKey, hash);
        proxyEURFToken.transferWithAuthorization(holder, spender, value, deadline, v, r, s);

        // 4. totalSupply will decrease.
        assertLt(proxyEURFToken.totalSupply(), beforeTotalSupply);
        console.log("proxyEURFToken.totalSupply(): ", proxyEURFToken.totalSupply());
        // proxyEURFToken.totalSupply():  390000000

    }
}
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {EURFToken} from "src/Token.sol";
import {ERC20ControlerMinterUpgradeable} from "src/ERC20ControlerMinterUpgradeable.sol";
import {FeesHandlerUpgradeable} from "src/FeesHandlerUpgradeable.sol";

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract TestEURFToken is Test {
    EURFToken proxyEURFToken;

    address owner = makeAddr("owner");
    address admin = makeAddr("admin");
    address masterMinter = makeAddr("MasterMinter");
    address minter = makeAddr("minter");
    address controller = makeAddr("controller");

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() virtual public {
        address proxyAdmin = address(new ProxyAdmin(owner));
        address implEURFToken = address(new EURFToken());

        proxyEURFToken = EURFToken(
            address(
                new TransparentUpgradeableProxy(
                    implEURFToken,
                    proxyAdmin,
                    abi.encodeWithSelector(EURFToken.initialize.selector)
                )
            )
        );

        role();
        mint();
    }

    function role() public {
        proxyEURFToken.setOwner(owner);

        vm.prank(owner);
        proxyEURFToken.setMasterMinter(masterMinter);
        assertEq(true, proxyEURFToken.isMasterMinter(masterMinter));

        vm.prank(masterMinter);
        proxyEURFToken.addMinter(minter, type(uint256).max);
        assertEq(proxyEURFToken.getMinterAllowance(minter), type(uint256).max);

        vm.prank(owner);
        proxyEURFToken.addController(controller);
        assertEq(true, proxyEURFToken.isController(controller));

        vm.prank(owner);
        proxyEURFToken.setAdministrator(admin);
        assertEq(true, proxyEURFToken.isAdministrator(admin));

    }

    function mint() public {
        vm.prank(masterMinter);
        proxyEURFToken.mint(alice, 100e6);
        assertEq(proxyEURFToken.balanceOf(alice), 100e6);

        vm.prank(masterMinter);
        proxyEURFToken.mint(bob, 100e6);
        assertEq(proxyEURFToken.balanceOf(bob), 100e6);

        vm.prank(minter);
        proxyEURFToken.mint(minter, 100e6);
        assertEq(proxyEURFToken.balanceOf(minter), 100e6);

        assertEq(proxyEURFToken.totalSupply(), 300e6);
    }
}
```

```solidity
bshyuunn@hyuunn-MacBook-Air foundry % forge test --mt test_poc_user_can_burn_token -vv  
Warning: This is a nightly build of Foundry. It is recommended to use the latest stable version. Visit https://book.getfoundry.sh/announcements for more information. 
To mute this warning set `FOUNDRY_DISABLE_NIGHTLY_WARNING` in your environment. 

[⠊] Compiling...
No files changed, compilation skipped

Ran 1 test for test/TestMetaTx.t.sol:TestMetaTx
[PASS] test_poc_user_can_burn_token() (gas: 139263)
Logs:
  proxyEURFToken.totalSupply():  400000000
  proxyEURFToken.totalSupply():  390000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.76ms (1.10ms CPU time)

Ran 1 test suite in 229.39ms (4.76ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Recommended mitigation steps

Include a validation check that reverts if spender (or recipient) is the zero address within the transferWithAuthorization function.

```diff
/**
 * @dev transferWithAuthorization function transferWithAuthorization if valid signed twa is provided.
 */
function transferWithAuthorization(
    address holder,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
) public virtual returns (bool) {
    if (block.timestamp > deadline) revert DeadLineExpired(deadline);
+		if (spender == address(0x0) || holder == address(0x0)) revert();

    bytes32 structHash = keccak256(abi.encode(_TWA_TYPEHASH, holder, spender, value, _useNonce(holder), deadline));

    bytes32 hash = _hashTypedDataV4(structHash);

    address signer = ECDSA.recover(hash, v, r, s);
    if (signer != holder) revert InvalidSignature();

    _update(holder, spender, value);

    return true;
}
```
