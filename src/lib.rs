use num_bigint::BigUint;

/// g^x mod p
/// output = N^EXP MOD P
pub fn  exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
  n.modpow(exponent, modulus)
}

/// output = s = k - cx mod q
pub fn solve(k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    if *k >= c * x {
        return (k - c * x).modpow(&BigUint::from(1u32), q);
    }
    return q - (k - c * x).modpow(&BigUint::from(1u32), q);
}

/// verify r1 = alpha^s * y1^c
/// r2 = beta^s * y2^c
pub fn verify(r1: &BigUint, r2: &BigUint, y1: &BigUint, y2: &BigUint, alpha: &BigUint, beta: &BigUint, s: &BigUint, c: &BigUint, p: &BigUint) -> bool {
    let cond1 = *r1 == alpha.modpow(s, p) * y1.modpow(c, p);
    let cond2 = *r2 == beta.modpow(s, p) * y2.modpow(c, p);
    cond1 == cond2
}
