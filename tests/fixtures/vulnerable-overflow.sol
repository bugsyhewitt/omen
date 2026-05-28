// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberate divide-before-multiply precision bug.
//
// reward() divides `amount` by `total` BEFORE multiplying by `rate`. Integer
// division truncates toward zero, so the division happens first and loses the
// fractional part, then the (now-truncated) quotient is multiplied — yielding a
// result far smaller than the intended `amount * rate / total`. This is the
// canonical arithmetic-precision bug the omen `overflow` class targets via
// Slither's `divide-before-multiply` detector. (Multiply first, then divide.)
contract VulnerableOverflow {
    function reward(uint256 amount, uint256 total, uint256 rate)
        public
        pure
        returns (uint256)
    {
        // BUG: division before multiplication truncates precision.
        return (amount / total) * rate;
    }
}
