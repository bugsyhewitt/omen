// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberate unprotected upgradeable implementation.
//
// This is a UUPS-style implementation contract. It is `Initializable` (the
// `initializer` modifier ensures initialize() runs once), it can delegatecall,
// and crucially it does NOT call `_disableInitializers()` in its constructor.
// An attacker can therefore call initialize() directly on the implementation,
// become the owner, and then upgrade the proxy to a malicious contract via the
// delegatecall path — seizing the whole proxy. This is the unprotected-upgrade
// pattern (the Wormhole uninitialized-implementation class of bug).
//
// Slither flags this via the `unprotected-upgrade` detector.

contract Initializable {
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "already initialized");
        _initialized = true;
        _;
    }
}

contract VulnerableUpgrade is Initializable {
    address public owner;

    // BUG: no constructor calling _disableInitializers(); the implementation
    // can be initialized by anyone, who then becomes owner.
    function initialize() external initializer {
        owner = msg.sender;
    }

    function upgradeToAndCall(address newImplementation, bytes memory data)
        external
    {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = newImplementation.delegatecall(data);
        require(ok, "upgrade failed");
    }
}
