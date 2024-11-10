# Trick or Treat (CodeHawks First Flights) - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)

- ## Medium Risk Findings
    - ### [M-01. Unsafe NFT Minting Using _mint() Instead of _safeMint()](#M-01)
- ## Low Risk Findings
    - ### [L-01. Incorrect Event Emission for Insufficient Payment in NFT Minting](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #27

### Dates: Oct 24th, 2024 - Oct 31st, 2024

[See more contest details here](https://codehawks.cyfrin.io/c/2024-10-trick-or-treat)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 0
- Medium: 1
- Low: 1



    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Unsafe NFT Minting Using _mint() Instead of _safeMint()            



## 01. Relevant GitHub Links

&#x20;

* <https://github.com/Cyfrin/2024-10-trick-or-treat/blob/9cb3955058cad9dd28a24eb5162a96d759bfa842/src/TrickOrTreat.sol#L80C1-L83C1>
* <https://github.com/Cyfrin/2024-10-trick-or-treat/blob/9cb3955058cad9dd28a24eb5162a96d759bfa842/src/TrickOrTreat.sol#L108C1-L116C1>

## 02. Summary

The contract uses the \_mint() function in multiple locations to mint NFTs. However, this can result in NFTs being sent to addresses that do not support ERC721 tokens, causing them to become irretrievable. To prevent this, \_safeMint() should be used instead to ensure that the recipient address can safely receive the NFT.

## 03. Vulnerability Details

The contract uses the \_mint() function in the following locations to mint NFTs:

```Solidity
uint256 tokenId = nextTokenId;
_mint(address(this), tokenId);
_setTokenURI(tokenId, treat.metadataURI);
```

```Solidity
function mintTreat(address recipient, Treat memory treat) internal {
    uint256 tokenId = nextTokenId;
    _mint(recipient, tokenId);
    _setTokenURI(tokenId, treat.metadataURI);
    nextTokenId += 1;

    emit Swapped(recipient, treat.name, tokenId);
}
```

The use of \_mint() directly sends the NFT to the specified address without verifying whether the recipient can receive ERC721 tokens. If the recipient is a contract that does not implement the IERC721Receiver interface, the NFT will be locked in that contract and become irretrievable. This could lead to significant asset loss for users.

Using \_safeMint() instead ensures that the recipient address is either an externally owned account (EOA) or a contract that properly implements the ERC721 receiver interface, preventing this kind of issue.

## 03. Impact

* Permanent Loss of NFTs: If an NFT is minted to a contract that does not support ERC721 tokens, it could be permanently lost or locked, with no way to retrieve it.
* User Frustration and Financial Loss: Users may lose access to valuable NFTs due to improper handling of the minting process.
* Potential Exploitation: An attacker could deliberately target contracts that cannot handle ERC721 tokens to cause NFT losses.

## 04. Proof of Concept

## 05. Tools Used

Manual Code Review and Foundry

## 06. Recommended Mitigation

1. Use \_safeMint() Instead of \_mint(): Replace all instances of \_mint() with \_safeMint() to ensure that the recipient is capable of receiving ERC721 tokens.

```Solidity
_safeMint(recipient, tokenId);  // Ensures recipient can handle ERC721 tokens
```


# Low Risk Findings

## <a id='L-01'></a>L-01. Incorrect Event Emission for Insufficient Payment in NFT Minting            



## 01. Relevant GitHub Links

&#x20;

* <https://github.com/Cyfrin/2024-10-trick-or-treat/blob/9cb3955058cad9dd28a24eb5162a96d759bfa842/src/TrickOrTreat.sol#L77C1-L89C63>

## 02. Summary

The contract emits a Swapped event even when a user has not sent enough ETH to complete the transaction. In such cases, the NFT is minted to the contract and marked as pending, rather than being directly swapped. This incorrect event can cause confusion by suggesting the transaction succeeded and the NFT was swapped to the user, while it’s actually still pending.

## 03. Vulnerability Details

When a user sends insufficient ETH, the contract mints an NFT to itself and marks it as pending by recording the user’s address and the amount paid. However, the contract still emits the Swapped event, which falsely signals that the transaction was successful and that the NFT was swapped to the user. This misrepresentation can lead to user confusion or misunderstandings about the transaction status.

```Solidity
} else {
    // User didn't send enough ETH
    // Mint NFT to contract and store pending purchase
    uint256 tokenId = nextTokenId;
    _mint(address(this), tokenId);
    _setTokenURI(tokenId, treat.metadataURI);
    nextTokenId += 1;

    pendingNFTs[tokenId] = msg.sender;
    pendingNFTsAmountPaid[tokenId] = msg.value;
    tokenIdToTreatName[tokenId] = _treatName;

    emit Swapped(msg.sender, _treatName, tokenId);
```

This event should only be emitted if the transaction completes successfully and the NFT is actually transferred to the user, not when it’s stored as a pending NFT.

## 03. Impact

* User Confusion and Misinterpretation: The Swapped event indicates a successful transaction, which can mislead users into thinking their purchase was completed when, in reality, the NFT is still pending.
* Potential Application Logic Errors: External systems or interfaces relying on events for status updates may misinterpret the transaction status, leading to potential errors in application logic or user interfaces.

## 04. Proof of Concept

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SpookySwap} from "../src/TrickOrTreat.sol";

contract TrickOrTreatTest is Test {
    SpookySwap spookyswapInstance;

    address owner;
    address user;

    function setUp() public {
        owner = vm.addr(0x1);
        user = vm.addr(0x2);

        vm.label(owner, "Owner");
        vm.deal(owner, 100 ether);

        vm.label(user, "User");
        vm.deal(user, 100 ether);

        SpookySwap.Treat[] memory TreatList;

        vm.prank(owner);
        spookyswapInstance = new SpookySwap(TreatList);
    }

    function test_IncorrectEvent() public {
        vm.prank(owner);
        spookyswapInstance.addTreat("Example", 1 ether, "test");

        uint256 tokenId = spookyswapInstance.nextTokenId();

        // random = 2
        // double price
        vm.warp(123456790);
        vm.prevrandao(987654324);
        
        vm.expectEmit(true, true, true, true);
				// Emits an event indicating the treat was swapped to the user
        emit SpookySwap.Swapped(user, "Example", tokenId);
        vm.prank(user);
        // Insufficient funds: treat purchase is pending until full payment is made
        spookyswapInstance.trickOrTreat{value: 1 ether}("Example");

        // user have no nft
        vm.assertEq(0, spookyswapInstance.balanceOf(user));
    }
}
```

## 05. Tools Used

Manual Code Review and Foundry

## 06. Recommended Mitigation

1. Emit a Different Event for Pending Transactions: Introduce a new event, such as PendingSwap, specifically for cases where the NFT is stored in the contract due to insufficient payment. This provides clarity on the transaction’s actual status.

```Solidity
emit PendingSwap(msg.sender, _treatName, tokenId);
```



