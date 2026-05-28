// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: a clean contract that should produce NO overflow or
// weak-randomness findings.
//
// reward() multiplies BEFORE dividing, preserving precision, so Slither's
// divide-before-multiply detector stays silent. There are no tautological
// comparisons and no on-chain randomness source, so neither the `overflow`
// nor the `weak-randomness` class should fire. This guards against false
// positives for both R8 classes.
contract CleanOverflow {
    function reward(uint256 amount, uint256 total, uint256 rate)
        public
        pure
        returns (uint256)
    {
        require(total != 0, "div by zero");
        // Multiply first, then divide: no precision loss.
        return (amount * rate) / total;
    }
}
