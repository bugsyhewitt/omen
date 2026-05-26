// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberately PRODIGAL contract.
// "Prodigal" (MAIAN, Nikolic et al., 2018) = a contract that leaks its
// Ether to arbitrary users who never deposited it. Here, anyone can call
// payout() and direct the entire balance to an address they control.
contract VulnerableProdigal {
    constructor() payable {}

    // No access control, no ownership check: an arbitrary caller can send
    // the contract's full balance to an arbitrary destination.
    function payout(address payable to) public {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
