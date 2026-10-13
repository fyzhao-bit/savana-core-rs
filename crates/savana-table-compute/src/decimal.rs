//! Exact decimal arithmetic as Python's `decimal` computes it in the
//! reference's calc context: precision 34, ROUND_HALF_EVEN, and exponents
//! unbounded (`MAX_EMAX`/`MIN_EMIN`), so rounding a result to 34 significant
//! digits is the only inexact step.
//!
//! A [`Dec`] is a value, not a decimal "cohort": trailing zeros are dropped,
//! because nothing the reference observes (comparisons, the limit check,
//! quantizing to cents) depends on a value's exponent. Every arithmetic
//! result is the exact result rounded once to 34 significant digits, as
//! libmpdec computes it; a value read from text stays exact (Python's
//! `Decimal(str)` is exact) until an operation rounds it.
//!
//! Work is linear in the operands' digits, except a product, which is
//! Karatsuba (`O(n^1.59)` in base-10^9 limbs) because an exact tie can need
//! every digit of it; a sum of far-apart magnitudes shortens the smaller
//! addend first, so the exponent gap costs nothing. Exponent arithmetic is
//! checked; an exponent outside `i64` (unreachable for any input that fits
//! in memory) gives no value.

use std::cmp::Ordering;

/// Significant digits of every arithmetic result.
pub(crate) const PRECISION: usize = 34;

#[derive(Clone, Debug)]
pub(crate) struct Dec {
    negative: bool,
    /// Most significant first; no leading or trailing zeros; empty for zero.
    digits: Vec<u8>,
    exponent: i64,
}

impl Dec {
    fn zero(negative: bool) -> Dec {
        Dec {
            negative,
            digits: Vec::new(),
            exponent: 0,
        }
    }

    /// `(-1)^negative × digits × 10^exponent`, with zeros trimmed.
    fn new(negative: bool, mut digits: Vec<u8>, exponent: i64) -> Option<Dec> {
        let lead = digits.iter().take_while(|d| **d == 0).count();
        digits.drain(..lead);
        if digits.is_empty() {
            return Some(Dec::zero(negative));
        }
        let trail = digits.iter().rev().take_while(|d| **d == 0).count();
        digits.truncate(digits.len() - trail);
        let exponent = exponent.checked_add(i64::try_from(trail).ok()?)?;
        Some(Dec {
            negative,
            digits,
            exponent,
        })
    }

    /// `Decimal(text)` for `-?[0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?`, exactly.
    pub(crate) fn parse(text: &str) -> Option<Dec> {
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (number, exponent) = match rest.find(['e', 'E']) {
            Some(at) => (&rest[..at], parse_exponent(&rest[at + 1..])?),
            None => (rest, 0),
        };
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if number.contains('.')
            && (fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()))
        {
            return None;
        }
        let digits: Vec<u8> = whole
            .bytes()
            .chain(fraction.bytes())
            .map(|b| b - b'0')
            .collect();
        let exponent = exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?;
        Dec::new(negative, digits, exponent)
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.digits.is_empty()
    }

    /// The place of the leading digit (`10^msd <= |self| < 10^(msd+1)`).
    fn msd(&self) -> Option<i64> {
        self.exponent
            .checked_add(i64::try_from(self.digits.len()).ok()? - 1)
    }

    /// The value rounded to [`PRECISION`] significant digits.
    pub(crate) fn rounded(&self) -> Option<Dec> {
        round(self.negative, self.digits.clone(), self.exponent, false)
    }

    /// `-x` (Python's unary minus, which rounds; minus zero is plus zero).
    pub(crate) fn neg(&self) -> Option<Dec> {
        if self.is_zero() {
            return Some(Dec::zero(false));
        }
        round(!self.negative, self.digits.clone(), self.exponent, false)
    }

    /// Whether `abs(self)` (rounded, as Python's `abs()` rounds) exceeds `limit`.
    pub(crate) fn abs_exceeds(&self, limit: &Dec) -> Option<bool> {
        let magnitude = round(false, self.digits.clone(), self.exponent, false)?;
        Some(cmp_magnitude(&magnitude, limit)? == Ordering::Greater)
    }

    /// The canonical text of a non-negative value: plain decimal digits,
    /// no exponent, no leading zeros, no trailing fractional zeros.
    pub(crate) fn plain(&self) -> String {
        let mut out = String::new();
        if self.negative && !self.is_zero() {
            out.push('-');
        }
        if self.is_zero() {
            out.push('0');
            return out;
        }
        let digits: String = self.digits.iter().map(|d| char::from(b'0' + d)).collect();
        if self.exponent >= 0 {
            out.push_str(&digits);
            out.extend(std::iter::repeat('0').take(self.exponent as usize));
            return out;
        }
        let fraction = self.exponent.unsigned_abs() as usize;
        if fraction >= digits.len() {
            out.push_str("0.");
            out.extend(std::iter::repeat('0').take(fraction - digits.len()));
            out.push_str(&digits);
        } else {
            let (whole, rest) = digits.split_at(digits.len() - fraction);
            out.push_str(whole);
            out.push('.');
            out.push_str(rest);
        }
        out
    }

    /// The reference's `_calc_format`: quantize to 0.01 (ROUND_HALF_EVEN),
    /// then an integer as an integer, else the decimals without trailing
    /// zeros.
    pub(crate) fn format_cents(&self) -> Option<String> {
        let cents = self.cents()?;
        let digits: String = if cents.is_empty() {
            "0".to_string()
        } else {
            cents.iter().map(|d| char::from(b'0' + d)).collect()
        };
        let padded = format!("{digits:0>3}");
        let (whole, fraction) = padded.split_at(padded.len() - 2);
        let whole = whole.trim_start_matches('0');
        let whole = if whole.is_empty() { "0" } else { whole };
        if fraction == "00" {
            // `str(int(value))`: a zero is never negative.
            let sign = if self.negative && whole != "0" {
                "-"
            } else {
                ""
            };
            return Some(format!("{sign}{whole}"));
        }
        let sign = if self.negative { "-" } else { "" };
        let fraction = fraction.trim_end_matches('0');
        Some(format!("{sign}{whole}.{fraction}"))
    }

    /// `|self| × 100` rounded half-even to an integer, as decimal digits
    /// (most significant first, no leading zeros, empty for zero).
    fn cents(&self) -> Option<Vec<u8>> {
        if self.is_zero() {
            return Some(Vec::new());
        }
        let shift = self.exponent.checked_add(2)?;
        if shift >= 0 {
            let mut digits = self.digits.clone();
            digits.extend(std::iter::repeat(0).take(usize::try_from(shift).ok()?));
            return Some(digits);
        }
        let dropped = usize::try_from(shift.unsigned_abs()).ok()?;
        let length = self.digits.len();
        if dropped > length {
            // Every digit is below the rounding digit, which is a zero.
            return Some(Vec::new());
        }
        let mut kept = self.digits[..length - dropped].to_vec();
        let round_digit = self.digits[length - dropped];
        let sticky = self.digits[length - dropped + 1..].iter().any(|d| *d != 0);
        let last_odd = kept.last().is_some_and(|d| d % 2 == 1);
        if round_up(round_digit, sticky, last_odd) {
            increment(&mut kept);
        }
        let lead = kept.iter().take_while(|d| **d == 0).count();
        kept.drain(..lead);
        Some(kept)
    }
}

/// `10^12`, the reference's CALC_LIMIT.
pub(crate) fn calc_limit() -> Dec {
    Dec {
        negative: false,
        digits: vec![1],
        exponent: 12,
    }
}

fn parse_exponent(text: &str) -> Option<i64> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: i64 = 0;
    for b in digits.bytes() {
        value = value.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
    }
    Some(if negative { -value } else { value })
}

fn round_up(round_digit: u8, sticky: bool, last_odd: bool) -> bool {
    match round_digit.cmp(&5) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => sticky || last_odd,
    }
}

/// Adds one to a most-significant-first digit string, growing it on carry.
fn increment(digits: &mut Vec<u8>) {
    for digit in digits.iter_mut().rev() {
        if *digit == 9 {
            *digit = 0;
        } else {
            *digit += 1;
            return;
        }
    }
    digits.insert(0, 1);
}

/// `(-1)^negative × digits × 10^exponent (+ a nonzero amount below the last
/// digit when `sticky`)` rounded half-even to [`PRECISION`] digits. `digits`
/// must not start with a zero; with `sticky` it must be longer than
/// [`PRECISION`].
fn round(negative: bool, mut digits: Vec<u8>, exponent: i64, sticky: bool) -> Option<Dec> {
    let length = digits.len();
    if length <= PRECISION {
        return Dec::new(negative, digits, exponent);
    }
    let round_digit = digits[PRECISION];
    let rest = sticky || digits[PRECISION + 1..].iter().any(|d| *d != 0);
    let last_odd = digits[PRECISION - 1] % 2 == 1;
    digits.truncate(PRECISION);
    if round_up(round_digit, rest, last_odd) {
        increment(&mut digits);
    }
    let exponent = exponent.checked_add(i64::try_from(length - PRECISION).ok()?)?;
    Dec::new(negative, digits, exponent)
}

/// Compares `|a|` and `|b|`.
fn cmp_magnitude(a: &Dec, b: &Dec) -> Option<Ordering> {
    Some(match (a.is_zero(), b.is_zero()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        // Same leading place: the digit strings align from the top, and
        // neither has trailing zeros, so a longer one is larger.
        (false, false) => a
            .msd()?
            .cmp(&b.msd()?)
            .then_with(|| a.digits.cmp(&b.digits)),
    })
}

/// Compares two values exactly (minus zero equals zero).
pub(crate) fn compare(a: &Dec, b: &Dec) -> Option<Ordering> {
    let sign = |x: &Dec| {
        if x.is_zero() {
            0
        } else if x.negative {
            -1
        } else {
            1
        }
    };
    let (sa, sb) = (sign(a), sign(b));
    if sa != sb {
        return Some(sa.cmp(&sb));
    }
    let magnitude = cmp_magnitude(a, b)?;
    Some(if sa < 0 {
        magnitude.reverse()
    } else {
        magnitude
    })
}

/// `a + b` (or `a - b` with `subtract`), rounded.
pub(crate) fn add(a: &Dec, b: &Dec, subtract: bool) -> Option<Dec> {
    let b_negative = b.negative != subtract;
    if a.is_zero() && b.is_zero() {
        // ROUND_HALF_EVEN: a zero sum is negative only from two negatives.
        return Some(Dec::zero(a.negative && b_negative));
    }
    if b.is_zero() {
        return a.rounded();
    }
    if a.is_zero() {
        return round(b_negative, b.digits.clone(), b.exponent, false);
    }
    let a = (a.negative, a.digits.as_slice(), a.exponent);
    let b = (b_negative, b.digits.as_slice(), b.exponent);
    let (a, b) = (shortened(a, b)?, shortened(b, a)?);
    let (a_msd, b_msd) = (msd_of(a)?, msd_of(b)?);
    let low = a.2.min(b.2);
    let top = a_msd.max(b_msd);
    // One more place for a carry.
    let width = usize::try_from(top.checked_sub(low)?.checked_add(2)?).ok()?;
    let mut x = aligned(a, low, width)?;
    let y = aligned(b, low, width)?;
    let negative = if a.0 == b.0 {
        add_in_place(&mut x, &y);
        a.0
    } else {
        match x.iter().rev().cmp(y.iter().rev()) {
            Ordering::Equal => return Some(Dec::zero(false)),
            Ordering::Greater => {
                sub_in_place(&mut x, &y);
                a.0
            }
            Ordering::Less => {
                let mut z = y;
                sub_in_place(&mut z, &x);
                x = z;
                b.0
            }
        }
    };
    x.reverse();
    let lead = x.iter().take_while(|d| **d == 0).count();
    x.drain(..lead);
    round(negative, x, low, false)
}

type Parts<'a> = (bool, &'a [u8], i64);

fn msd_of(x: Parts) -> Option<i64> {
    x.2.checked_add(i64::try_from(x.1.len()).ok()? - 1)
}

/// `small` as an addend of `big`, shortened when every one of its digits
/// lies below both `big`'s last digit and the 34-digit window of any sum:
/// then the sum lies strictly between two neighbours that are multiples of
/// a place no rounding boundary falls between, and `±10^(cut-1)` lands in
/// the same gap, so it rounds the same way.
fn shortened<'a>(small: Parts<'a>, big: Parts<'a>) -> Option<Parts<'a>> {
    const ONE: &[u8] = &[1];
    let (small_msd, big_msd) = (msd_of(small)?, msd_of(big)?);
    if small_msd >= big_msd {
        return Some(small);
    }
    let cut = big.2.min(big_msd.checked_sub(35)?).checked_sub(1)?;
    if small_msd < cut {
        return Some((small.0, ONE, cut.checked_sub(1)?));
    }
    Some(small)
}

/// The digits of `x` least significant first, placed from `low` in `width` places.
fn aligned(x: Parts, low: i64, width: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; width];
    let offset = usize::try_from(x.2.checked_sub(low)?).ok()?;
    for (at, digit) in x.1.iter().rev().enumerate() {
        *out.get_mut(offset.checked_add(at)?)? = *digit;
    }
    Some(out)
}

fn add_in_place(x: &mut [u8], y: &[u8]) {
    let mut carry = 0;
    for (a, b) in x.iter_mut().zip(y) {
        let sum = *a + *b + carry;
        *a = sum % 10;
        carry = sum / 10;
    }
}

/// `x -= y` for least-significant-first digits with `x >= y`.
fn sub_in_place(x: &mut [u8], y: &[u8]) {
    let mut borrow = 0;
    for (at, a) in x.iter_mut().enumerate() {
        let b = y.get(at).copied().unwrap_or(0) + borrow;
        if *a >= b {
            *a -= b;
            borrow = 0;
        } else {
            *a = *a + 10 - b;
            borrow = 1;
        }
    }
}

/// `a × b`, rounded.
pub(crate) fn mul(a: &Dec, b: &Dec) -> Option<Dec> {
    let negative = a.negative != b.negative;
    if a.is_zero() || b.is_zero() {
        return Some(Dec::zero(negative));
    }
    let product = multiply_digits(&a.digits, &b.digits);
    round(
        negative,
        product,
        a.exponent.checked_add(b.exponent)?,
        false,
    )
}

/// `a / b` for a nonzero `b`, correctly rounded.
pub(crate) fn div(a: &Dec, b: &Dec) -> Option<Dec> {
    let negative = a.negative != b.negative;
    if a.is_zero() {
        return Some(Dec::zero(negative));
    }
    // A dividend of len(b) + 35 digits gives a quotient of 35 or 36 digits:
    // one more than the precision, with the remainder as the sticky part.
    let length = a.digits.len();
    let wanted = b.digits.len() + PRECISION + 1;
    let (dividend, mut sticky) = if wanted >= length {
        let mut digits = a.digits.clone();
        digits.resize(wanted, 0);
        (digits, false)
    } else {
        // The dropped digits end in a nonzero digit.
        (a.digits[..wanted].to_vec(), true)
    };
    let shift = i64::try_from(wanted).ok()? - i64::try_from(length).ok()?;
    let (quotient, exact) = divide_digits(&dividend, &b.digits);
    sticky |= !exact;
    let exponent = a.exponent.checked_sub(b.exponent)?.checked_sub(shift)?;
    round(negative, quotient, exponent, sticky)
}

/// Long division of most-significant-first digit strings (no leading
/// zeros; `divisor` nonempty) whose quotient is short: linear in the
/// divisor's length per quotient digit.
fn divide_digits(dividend: &[u8], divisor: &[u8]) -> (Vec<u8>, bool) {
    let start = (divisor.len() - 1).min(dividend.len());
    let mut remainder: Vec<u8> = dividend[..start].to_vec();
    let mut quotient = Vec::with_capacity(dividend.len() - start);
    for &digit in &dividend[start..] {
        if !(remainder.is_empty() && digit == 0) {
            remainder.push(digit);
        }
        let mut count = 0;
        while !less(&remainder, divisor) {
            subtract_msd(&mut remainder, divisor);
            count += 1;
        }
        quotient.push(count);
    }
    let lead = quotient.iter().take_while(|d| **d == 0).count();
    quotient.drain(..lead);
    (quotient, remainder.is_empty())
}

/// `a < b` for most-significant-first digit strings without leading zeros.
fn less(a: &[u8], b: &[u8]) -> bool {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b)) == Ordering::Less
}

/// `a -= b` for most-significant-first digit strings, `a >= b`, leaving no
/// leading zeros.
fn subtract_msd(a: &mut Vec<u8>, b: &[u8]) {
    let offset = a.len() - b.len();
    let mut borrow = 0;
    for at in (0..a.len()).rev() {
        let subtrahend = if at >= offset { b[at - offset] } else { 0 } + borrow;
        if a[at] >= subtrahend {
            a[at] -= subtrahend;
            borrow = 0;
        } else {
            a[at] = a[at] + 10 - subtrahend;
            borrow = 1;
        }
    }
    let lead = a.iter().take_while(|d| **d == 0).count();
    a.drain(..lead);
}

const LIMB: u64 = 1_000_000_000;
/// Below this many limbs in the shorter factor, schoolbook beats Karatsuba.
const KARATSUBA_LIMBS: usize = 40;
/// Karatsuba halves the longer factor at every level, so 48 levels cover
/// any operand that fits in memory; deeper calls (never reached) fall back
/// to schoolbook rather than recursing further.
const KARATSUBA_DEPTH: u32 = 48;

/// The product of two most-significant-first digit strings, through
/// base-10^9 limbs.
pub(crate) fn multiply_digits(a: &[u8], b: &[u8]) -> Vec<u8> {
    from_limbs(&multiply_limbs(&to_limbs(a), &to_limbs(b), 0))
}

/// The product of two least-significant-first base-10^9 limb strings, as
/// `x.len() + y.len()` limbs: Karatsuba down to schoolbook.
fn multiply_limbs(x: &[u64], y: &[u64], depth: u32) -> Vec<u64> {
    let mut product = vec![0u64; x.len() + y.len()];
    if x.len().min(y.len()) < KARATSUBA_LIMBS || depth >= KARATSUBA_DEPTH {
        schoolbook(x, y, &mut product);
        return product;
    }
    let (long, short) = if x.len() >= y.len() { (x, y) } else { (y, x) };
    let half = long.len() / 2;
    if short.len() <= half {
        // Unbalanced: split only the longer factor.
        add_shifted(
            &mut product,
            &multiply_limbs(&long[..half], short, depth + 1),
            0,
        );
        add_shifted(
            &mut product,
            &multiply_limbs(&long[half..], short, depth + 1),
            half,
        );
        return product;
    }
    let (x0, x1) = long.split_at(half);
    let (y0, y1) = short.split_at(half);
    let low = multiply_limbs(x0, y0, depth + 1);
    let high = multiply_limbs(x1, y1, depth + 1);
    // (x0 + x1)(y0 + y1) - low - high = x0·y1 + x1·y0 >= 0
    let mut middle = multiply_limbs(&sum_limbs(x0, x1), &sum_limbs(y0, y1), depth + 1);
    subtract_limbs(&mut middle, &low);
    subtract_limbs(&mut middle, &high);
    add_shifted(&mut product, &low, 0);
    add_shifted(&mut product, &middle, half);
    add_shifted(&mut product, &high, 2 * half);
    product
}

fn schoolbook(x: &[u64], y: &[u64], product: &mut [u64]) {
    for (i, &xi) in x.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &yj) in y.iter().enumerate() {
            // At most (10^9 - 1) + (10^9 - 1)^2 + (10^9 - 1) = 10^18 - 1, so
            // the carry stays below 10^9.
            let t = product[i + j] + xi * yj + carry;
            product[i + j] = t % LIMB;
            carry = t / LIMB;
        }
        // No earlier row reached this limb.
        product[i + y.len()] = carry;
    }
}

fn sum_limbs(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u64;
    for at in 0..a.len().max(b.len()) {
        let t = a.get(at).copied().unwrap_or(0) + b.get(at).copied().unwrap_or(0) + carry;
        out.push(t % LIMB);
        carry = t / LIMB;
    }
    out.push(carry);
    out
}

/// `a -= b` for limb strings with `a >= b` in value.
fn subtract_limbs(a: &mut [u64], b: &[u64]) {
    let mut borrow = 0u64;
    for (at, limb) in a.iter_mut().enumerate() {
        let subtrahend = b.get(at).copied().unwrap_or(0) + borrow;
        if subtrahend == 0 && at >= b.len() {
            break;
        }
        if *limb >= subtrahend {
            *limb -= subtrahend;
            borrow = 0;
        } else {
            *limb = *limb + LIMB - subtrahend;
            borrow = 1;
        }
    }
}

/// `product += part × 10^(9·offset)`; the sum fits `product` (any limbs of
/// `part` past its end are zero).
fn add_shifted(product: &mut [u64], part: &[u64], offset: usize) {
    let mut carry = 0u64;
    let mut at = offset;
    for &limb in part {
        let Some(slot) = product.get_mut(at) else {
            break;
        };
        let t = *slot + limb + carry;
        *slot = t % LIMB;
        carry = t / LIMB;
        at += 1;
    }
    while carry > 0 {
        let Some(slot) = product.get_mut(at) else {
            break;
        };
        let t = *slot + carry;
        *slot = t % LIMB;
        carry = t / LIMB;
        at += 1;
    }
}

fn to_limbs(digits: &[u8]) -> Vec<u64> {
    digits
        .rchunks(9)
        .map(|chunk| chunk.iter().fold(0u64, |acc, d| acc * 10 + u64::from(*d)))
        .collect()
}

fn from_limbs(limbs: &[u64]) -> Vec<u8> {
    let mut digits = Vec::with_capacity(limbs.len() * 9);
    for &limb in limbs.iter().rev() {
        let mut chunk = [0u8; 9];
        let mut value = limb;
        for slot in chunk.iter_mut().rev() {
            *slot = (value % 10) as u8;
            value /= 10;
        }
        digits.extend_from_slice(&chunk);
    }
    let lead = digits.iter().take_while(|d| **d == 0).count();
    digits.drain(..lead);
    digits
}
