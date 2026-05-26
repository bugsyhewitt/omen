// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: a CLEAN access-control contract (negative control).
//
// Ownership is transferred only through an `onlyOwner`-guarded function that
// emits an event, and the privileged withdraw is likewise guarded. There is
// no tx.origin usage anywhere. omen's access-control and tx-origin checks
// should produce NO findings here.
//
// Note: this fixture deliberately does NOT carry a
// `@custom:security write-protection` NatSpec annotation. Slither's
// `protected-vars` detector keys off that annotation and (by design) does not
// exempt the constructor, so any annotated contract trips on its own
// constructor. A genuinely clean contract that simply guards its mutators is
// the correct negative control: there is nothing for protected-vars to check,
// no missing access-control event, and no tx.origin auth.
contract CleanAccessControl {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function withdraw(address payable to) public onlyOwner {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
