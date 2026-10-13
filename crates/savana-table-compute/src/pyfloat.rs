//! Python float semantics the reference relies on: `repr(float)`, the
//! reference's `_format`, and CPython 3.12's builtin `sum()` over floats.

use std::cmp::Ordering;

/// Python `repr(x)`: the shortest digits that read back as `x`, positional
/// when the decimal exponent is in `-4..16` (with at least one fractional
/// digit), else `d[.ddd]e±XX` with at least two exponent digits.
pub(crate) fn repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sign = if x.is_sign_negative() { "-" } else { "" };
    if x == 0.0 {
        return format!("{sign}0.0");
    }
    let (digits, point) = shortest(x.abs());
    let digits: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
    let point = i64::from(point); // value = 0.DIGITS × 10^point
    let exponent = point - 1;
    let count = digits.len() as i64;
    if !(-4 < point && point <= 16) {
        let (first, rest) = digits.split_at(1);
        let mut out = format!("{sign}{first}");
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let magnitude = exponent.unsigned_abs();
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        out.push_str(&format!("e{exponent_sign}{magnitude:02}"));
        return out;
    }
    if point <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-point) as usize))
    } else if point >= count {
        format!("{sign}{digits}{}.0", "0".repeat((point - count) as usize))
    } else {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{sign}{whole}.{fraction}")
    }
}

/// The shortest decimal digits that read back as the finite `x > 0`, as
/// `(digits, point)` with `x ≈ 0.DIGITS × 10^point`: CPython's `repr`
/// (David Gay's `dtoa` mode 0). This is Burger and Dybvig's free-format
/// algorithm in exact integer arithmetic: the rounding interval is closed
/// when the significand is even, and when both the last digit and the next
/// one up would read back as `x`, the nearer wins and an exact tie goes to
/// the even digit (Rust's own shortest formatting rounds such ties up).
fn shortest(x: f64) -> (Vec<u8>, i32) {
    let bits = x.to_bits();
    let field = (bits >> 52) & 0x7ff;
    let fraction = bits & ((1u64 << 52) - 1);
    let (significand, exponent) = if field == 0 {
        (fraction, -1074i32)
    } else {
        (fraction | (1u64 << 52), field as i32 - 1075)
    };
    let closed = significand % 2 == 0;
    // A power of two above the smallest normal has a gap below it half the one above.
    let uneven = field > 1 && fraction == 0;
    // x = r / s; the rounding interval is (x - minus / s, x + plus / s).
    let (mut r, mut s, mut plus, mut minus);
    if exponent >= 0 {
        let gap = Big::from_u64(1).shl(exponent as usize);
        let extra = if uneven { 2 } else { 1 };
        r = Big::from_u64(significand).shl(exponent as usize + extra);
        s = Big::from_u64(1).shl(extra);
        plus = gap.shl(extra - 1);
        minus = Big::from_u64(1).shl(exponent as usize);
    } else {
        let extra = if uneven { 2 } else { 1 };
        r = Big::from_u64(significand).shl(extra);
        s = Big::from_u64(1).shl(extra + exponent.unsigned_abs() as usize);
        plus = Big::from_u64(1).shl(extra - 1);
        minus = Big::from_u64(1);
    }
    let reaches = |r: &Big, plus: &Big, s: &Big| {
        let high = r.add(plus);
        if closed {
            high.cmp(s) != Ordering::Less
        } else {
            high.cmp(s) == Ordering::Greater
        }
    };
    // The point: the least `point` with x's interval below 10^point.
    let mut point = x.log10().ceil() as i32;
    if point >= 0 {
        s.mul_pow10(point.unsigned_abs());
    } else {
        r.mul_pow10(point.unsigned_abs());
        plus.mul_pow10(point.unsigned_abs());
        minus.mul_pow10(point.unsigned_abs());
    }
    while reaches(&r, &plus, &s) {
        s.mul_small(10);
        point += 1;
    }
    loop {
        let (mut r10, mut plus10) = (r.clone(), plus.clone());
        r10.mul_small(10);
        plus10.mul_small(10);
        if reaches(&r10, &plus10, &s) {
            break;
        }
        r = r10;
        plus = plus10;
        minus.mul_small(10);
        point -= 1;
    }
    let mut digits = Vec::new();
    // At most 17 digits are ever needed; the bound only keeps the loop finite.
    while digits.len() < 800 {
        r.mul_small(10);
        plus.mul_small(10);
        minus.mul_small(10);
        let mut digit = 0u8;
        while r.cmp(&s) != Ordering::Less {
            r.sub_assign(&s);
            digit += 1;
        }
        let low = match r.cmp(&minus) {
            Ordering::Less => true,
            Ordering::Equal => closed,
            Ordering::Greater => false,
        };
        let high = reaches(&r, &plus, &s);
        match (low, high) {
            (false, false) => {
                digits.push(digit);
                continue;
            }
            (true, false) => digits.push(digit),
            (false, true) => digits.push(digit + 1),
            (true, true) => digits.push(match r.clone().shl(1).cmp(&s) {
                Ordering::Less => digit,
                Ordering::Greater => digit + 1,
                Ordering::Equal => digit + digit % 2,
            }),
        }
        break;
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    (digits, point)
}

/// An unsigned integer in base 2^32 limbs, least significant first, with no
/// high zero limb.
#[derive(Clone, Debug)]
struct Big(Vec<u32>);

impl Big {
    fn from_u64(value: u64) -> Big {
        let mut big = Big(vec![value as u32, (value >> 32) as u32]);
        big.trim();
        big
    }

    fn trim(&mut self) {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    fn shl(self, bits: usize) -> Big {
        let (limbs, shift) = (bits / 32, bits % 32);
        let mut out = vec![0u32; limbs];
        let mut carry = 0u32;
        for limb in self.0 {
            if shift == 0 {
                out.push(limb);
            } else {
                out.push((limb << shift) | carry);
                carry = limb >> (32 - shift);
            }
        }
        if carry > 0 {
            out.push(carry);
        }
        let mut big = Big(out);
        big.trim();
        big
    }

    fn mul_small(&mut self, factor: u32) {
        let mut carry = 0u64;
        for limb in self.0.iter_mut() {
            let product = u64::from(*limb) * u64::from(factor) + carry;
            *limb = product as u32;
            carry = product >> 32;
        }
        if carry > 0 {
            self.0.push(carry as u32);
        }
    }

    fn mul_pow10(&mut self, power: u32) {
        for _ in 0..power / 9 {
            self.mul_small(1_000_000_000);
        }
        self.mul_small(10u32.pow(power % 9));
    }

    fn add(&self, other: &Big) -> Big {
        let mut out = Vec::with_capacity(self.0.len().max(other.0.len()) + 1);
        let mut carry = 0u64;
        for at in 0..self.0.len().max(other.0.len()) {
            let sum = u64::from(self.0.get(at).copied().unwrap_or(0))
                + u64::from(other.0.get(at).copied().unwrap_or(0))
                + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        if carry > 0 {
            out.push(carry as u32);
        }
        let mut big = Big(out);
        big.trim();
        big
    }

    /// `self -= other` for `self >= other`.
    fn sub_assign(&mut self, other: &Big) {
        let mut borrow = 0i64;
        for (at, limb) in self.0.iter_mut().enumerate() {
            let difference =
                i64::from(*limb) - i64::from(other.0.get(at).copied().unwrap_or(0)) - borrow;
            borrow = i64::from(difference < 0);
            *limb = (difference + (borrow << 32)) as u32;
        }
        self.trim();
    }

    fn cmp(&self, other: &Big) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }
}

/// The reference's `_format`: an integral value below 1e15 as an integer,
/// anything else with two decimals and trailing zeros (then the point)
/// removed. A non-finite number has no text.
pub(crate) fn format_number(x: f64) -> String {
    if !x.is_finite() {
        return String::new();
    }
    if x == x.trunc() && x.abs() < 1e15 {
        // |x| < 1e15, so the conversion is exact; -0.0 gives "0".
        return format!("{}", x as i64);
    }
    let fixed = format!("{x:.2}");
    fixed
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

/// `sum(values)` as CPython 3.12 computes it for floats: the start is the
/// int 0, so the first float is added to 0.0, and the rest are added with
/// Neumaier's compensation, which joins the sum only when it is nonzero
/// and finite. No value gives the int 0, which formats like 0.0.
pub(crate) fn sum(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return 0.0;
    };
    let mut total = 0.0 + first;
    let mut compensation = 0.0;
    for x in values {
        let t = total + x;
        if total.abs() >= x.abs() {
            compensation += (total - t) + x;
        } else {
            compensation += (x - t) + total;
        }
        total = t;
    }
    if compensation != 0.0 && compensation.is_finite() {
        total += compensation;
    }
    total
}
