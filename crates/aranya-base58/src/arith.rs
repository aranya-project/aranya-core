// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Returns the 128-bit result of `x*y + c` as (hi, lo).
pub(crate) const fn mul_add_ww(x: u64, y: u64, c: u64) -> (u64, u64) {
    let z = (x as u128).wrapping_mul(y as u128).wrapping_add(c as u128);
    ((z >> 64) as u64, z as u64)
}

/// Returns the 128-bit product of `x*y` as (hi, lo).
pub(crate) const fn mul64(x: u64, y: u64) -> (u64, u64) {
    let z = (x as u128).wrapping_mul(y as u128);
    ((z >> 64) as u64, z as u64)
}

/// Returns `(q, r)` such that
///
/// ```text
/// q = (x<<_W + x0 - r) / y
/// m = floor((_B^2 -1) / d - _B)
/// for x1 < y
/// ```
///
/// An approximate reciprocal with a reference to "Improved
/// Division by Invariant Integers (IEEE Transactions on
/// Computers, 11 Jun. 2010)"
pub(crate) const fn div_ww(mut x1: u64, mut x0: u64, mut y: u64, m: u64) -> (u64, u64) {
    assert!(x1 < y);

    let s = y.leading_zeros();
    if s != 0 {
        x1 = x1 << s | x0 >> 64_u32.wrapping_sub(s);
        x0 <<= s;
        y <<= s;
    }
    let d = y;
    // We know that
    //   m = ⎣(B^2-1)/d⎦-B
    //   ⎣(B^2-1)/d⎦ = m+B
    //   (B^2-1)/d = m+B+delta1    0 <= delta1 <= (d-1)/d
    //   B^2/d = m+B+delta2        0 <= delta2 <= 1
    // The quotient we're trying to compute is
    //   quotient = ⎣(x1*B+x0)/d⎦
    //            = ⎣(x1*B*(B^2/d)+x0*(B^2/d))/B^2⎦
    //            = ⎣(x1*B*(m+B+delta2)+x0*(m+B+delta2))/B^2⎦
    //            = ⎣(x1*m+x1*B+x0)/B + x0*m/B^2 + delta2*(x1*B+x0)/B^2⎦
    // The latter two terms of this three-term sum are between 0 and 1.
    // So we can compute just the first term, and we will be low by at most 2.
    let (t1, t0) = mul64(m, x1);
    let (_, c) = t0.overflowing_add(x0);
    let t1 = t1.wrapping_add(x1).wrapping_add(c as u64);
    // The quotient is either t1, t1+1, or t1+2.
    // We'll try t1 and adjust if needed.
    let mut qq = t1;
    // compute remainder r=x-d*q.
    let (dq1, dq0) = mul64(d, qq);
    let (mut r0, b) = x0.overflowing_sub(dq0);
    let r1 = x1.wrapping_sub(dq1).wrapping_sub(b as u64);
    // The remainder we just computed is bounded above by B+d:
    // r = x1*B + x0 - d*q.
    //   = x1*B + x0 - d*⎣(x1*m+x1*B+x0)/B⎦
    //   = x1*B + x0 - d*((x1*m+x1*B+x0)/B-alpha)                                   0 <= alpha < 1
    //   = x1*B + x0 - x1*d/B*m                         - x1*d - x0*d/B + d*alpha
    //   = x1*B + x0 - x1*d/B*⎣(B^2-1)/d-B⎦             - x1*d - x0*d/B + d*alpha
    //   = x1*B + x0 - x1*d/B*⎣(B^2-1)/d-B⎦             - x1*d - x0*d/B + d*alpha
    //   = x1*B + x0 - x1*d/B*((B^2-1)/d-B-beta)        - x1*d - x0*d/B + d*alpha   0 <= beta < 1
    //   = x1*B + x0 - x1*B + x1/B + x1*d + x1*d/B*beta - x1*d - x0*d/B + d*alpha
    //   =        x0        + x1/B        + x1*d/B*beta        - x0*d/B + d*alpha
    //   = x0*(1-d/B) + x1*(1+d*beta)/B + d*alpha
    //   <  B*(1-d/B) +  d*B/B          + d          because x0<B (and 1-d/B>0), x1<d, 1+d*beta<=B, alpha<1
    //   =  B - d     +  d              + d
    //   = B+d
    // So r1 can only be 0 or 1. If r1 is 1, then we know q was too small.
    // Add 1 to q and subtract d from r. That guarantees that r is <B, so
    // we no longer need to keep track of r1.
    if r1 != 0 {
        qq = qq.wrapping_add(1);
        r0 = r0.wrapping_sub(d);
    }
    // If the remainder is still too large, increment q one more
    // time.
    if r0 >= d {
        qq = qq.wrapping_add(1);
        r0 = r0.wrapping_sub(d);
    }
    (qq, r0 >> s)
}
