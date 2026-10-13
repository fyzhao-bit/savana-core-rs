//! The "calc" output: an arithmetic expression over the first number of
//! each input, evaluated exactly (`parse_calc`, `_calc_value`, `_calc_eval`
//! and `_calc_format` in the reference).
//!
//! Grammar (at most [`MAX_CALC_TOKENS`] tokens, nesting at most
//! [`MAX_CALC_DEPTH`]):
//!
//! ```text
//! expression := term (("+" | "-") term)*
//! term       := unary (("*" | "/") unary)*
//! unary      := "-" unary | atom
//! atom       := number | "#1".."#4" | ("min" | "max") "(" expression ("," expression)+ ")"
//!             | "(" expression ")"
//! number     := [0-9]+ ("." [0-9]+)?
//! ```

use std::cmp::Ordering;

use crate::decimal::{self, Dec};
use crate::json::{self, Value};
use crate::pyfloat;
use crate::table;
use crate::ComputeSpecError;

pub(crate) const MAX_CALC_TOKENS: usize = 64;
pub(crate) const MAX_CALC_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Number(Dec),
    /// An input, 1-based.
    Ref(usize),
    Neg(Box<Node>),
    Binary(u8, Box<Node>, Box<Node>),
    /// `min(...)` when true, `max(...)` when false.
    Extreme(bool, Vec<Node>),
}

#[derive(Debug, Clone, PartialEq)]
enum Token<'a> {
    Number(&'a str),
    Ref(usize),
    Min,
    Max,
    Symbol(u8),
}

/// `_calc_tokens`: optional whitespace, then a number, `#1`..`#4`, `min`,
/// `max` or one of `-+*/(),`, until the text ends.
fn tokens(text: &str) -> Result<Vec<Token<'_>>, ComputeSpecError> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        rest = rest.trim_start_matches(table::is_space);
        let bytes = rest.as_bytes();
        let (token, length) = match bytes.first() {
            Some(b'0'..=b'9') => {
                let mut end = digits_end(bytes, 0);
                if bytes.get(end) == Some(&b'.')
                    && bytes.get(end + 1).is_some_and(u8::is_ascii_digit)
                {
                    end = digits_end(bytes, end + 1);
                }
                (Token::Number(&rest[..end]), end)
            }
            Some(b'#') => match bytes.get(1) {
                Some(digit @ b'1'..=b'4') => (Token::Ref(usize::from(digit - b'0')), 2),
                _ => return Err(ComputeSpecError::Spec),
            },
            Some(_) if rest.starts_with("min") => (Token::Min, 3),
            Some(_) if rest.starts_with("max") => (Token::Max, 3),
            Some(symbol @ (b'-' | b'+' | b'*' | b'/' | b'(' | b')' | b',')) => {
                (Token::Symbol(*symbol), 1)
            }
            _ => return Err(ComputeSpecError::Spec),
        };
        out.push(token);
        rest = &rest[length..];
        if out.len() > MAX_CALC_TOKENS {
            return Err(ComputeSpecError::Spec);
        }
    }
    Ok(out)
}

fn digits_end(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    at
}

/// `parse_calc(text, inputs)`: the expression's tree. Tokenizing comes
/// first, then the first error in reading order wins.
pub(crate) fn parse(text: &str, inputs: usize) -> Result<Node, ComputeSpecError> {
    let tokens = tokens(text)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        inputs,
    };
    let tree = parser.expression(0)?;
    if parser.at != tokens.len() {
        return Err(ComputeSpecError::Spec);
    }
    Ok(tree)
}

struct Parser<'t, 'a> {
    tokens: &'t [Token<'a>],
    at: usize,
    inputs: usize,
}

impl<'a> Parser<'_, 'a> {
    fn peek_symbol(&self) -> Option<u8> {
        match self.tokens.get(self.at) {
            Some(Token::Symbol(symbol)) => Some(*symbol),
            _ => None,
        }
    }

    fn take(&mut self) -> Result<Token<'a>, ComputeSpecError> {
        let token = self
            .tokens
            .get(self.at)
            .cloned()
            .ok_or(ComputeSpecError::Spec)?;
        self.at += 1;
        Ok(token)
    }

    fn take_symbol(&mut self, symbol: u8) -> Result<(), ComputeSpecError> {
        if self.peek_symbol() != Some(symbol) {
            return Err(ComputeSpecError::Spec);
        }
        self.at += 1;
        Ok(())
    }

    fn expression(&mut self, depth: usize) -> Result<Node, ComputeSpecError> {
        if depth > MAX_CALC_DEPTH {
            return Err(ComputeSpecError::Spec);
        }
        let mut tree = self.term(depth)?;
        while let Some(op @ (b'+' | b'-')) = self.peek_symbol() {
            self.at += 1;
            tree = Node::Binary(op, Box::new(tree), Box::new(self.term(depth)?));
        }
        Ok(tree)
    }

    fn term(&mut self, depth: usize) -> Result<Node, ComputeSpecError> {
        let mut tree = self.unary(depth)?;
        while let Some(op @ (b'*' | b'/')) = self.peek_symbol() {
            self.at += 1;
            tree = Node::Binary(op, Box::new(tree), Box::new(self.unary(depth)?));
        }
        Ok(tree)
    }

    fn unary(&mut self, depth: usize) -> Result<Node, ComputeSpecError> {
        if self.peek_symbol() == Some(b'-') {
            self.at += 1;
            if depth + 1 > MAX_CALC_DEPTH {
                return Err(ComputeSpecError::Spec);
            }
            return Ok(Node::Neg(Box::new(self.unary(depth + 1)?)));
        }
        self.atom(depth)
    }

    fn atom(&mut self, depth: usize) -> Result<Node, ComputeSpecError> {
        match self.take()? {
            Token::Number(text) => Dec::parse(text)
                .map(Node::Number)
                .ok_or(ComputeSpecError::Spec),
            Token::Ref(input) => {
                if input > self.inputs {
                    return Err(ComputeSpecError::Input);
                }
                Ok(Node::Ref(input))
            }
            function @ (Token::Min | Token::Max) => {
                self.take_symbol(b'(')?;
                let mut arguments = vec![self.expression(depth + 1)?];
                while self.peek_symbol() == Some(b',') {
                    self.at += 1;
                    arguments.push(self.expression(depth + 1)?);
                }
                self.take_symbol(b')')?;
                if arguments.len() < 2 {
                    return Err(ComputeSpecError::Spec);
                }
                Ok(Node::Extreme(function == Token::Min, arguments))
            }
            Token::Symbol(b'(') => {
                let tree = self.expression(depth + 1)?;
                self.take_symbol(b')')?;
                Ok(tree)
            }
            Token::Symbol(_) => Err(ComputeSpecError::Spec),
        }
    }
}

/// Every number the expression writes itself (`calc_constants`).
pub(crate) fn constants<'n>(tree: &'n Node, found: &mut Vec<&'n Dec>) {
    match tree {
        Node::Number(value) => found.push(value),
        Node::Ref(_) => {}
        Node::Neg(inner) => constants(inner, found),
        Node::Binary(_, left, right) => {
            constants(left, found);
            constants(right, found);
        }
        Node::Extreme(_, arguments) => arguments
            .iter()
            .for_each(|argument| constants(argument, found)),
    }
}

/// `_calc_value`: the first number of one input, exactly: an extraction's
/// or computation's value (`{"text": ...}`), a JSON number, or plain text.
/// `None` without a number or beyond the limit.
pub(crate) fn input_value(text: &str) -> Option<Dec> {
    let parsed = json::parse(text);
    let value = match &parsed {
        Some(object @ Value::Object(_)) => object.get("text")?,
        Some(value) => value,
        None => return limited(table::first_number(text).and_then(decimal_text)?),
    };
    let number = match value {
        Value::Int { negative, digits } => {
            Dec::parse(&format!("{}{digits}", if *negative { "-" } else { "" }))?
        }
        Value::Float(x) if x.is_finite() => Dec::parse(&pyfloat::repr(*x))?,
        Value::Str(text) => table::first_number(text).and_then(decimal_text)?,
        _ => return None,
    };
    limited(number)
}

/// A `_NUMBER` match without its commas, as a decimal.
fn decimal_text(found: &str) -> Option<Dec> {
    Dec::parse(&found.replace(',', ""))
}

fn limited(number: Dec) -> Option<Dec> {
    (!number.abs_exceeds(&decimal::calc_limit())?).then_some(number)
}

/// `_calc_eval`: the tree's value over the inputs' numbers, or `None` when
/// an input has none, a divisor is zero, or a value (after each step)
/// exceeds the limit.
pub(crate) fn evaluate(tree: &Node, values: &[Option<Dec>]) -> Option<Dec> {
    let result = match tree {
        Node::Number(value) => value.clone(),
        Node::Ref(input) => values.get(input.checked_sub(1)?)?.clone()?,
        Node::Neg(inner) => evaluate(inner, values)?.neg()?,
        Node::Extreme(is_min, arguments) => {
            let found: Vec<Dec> = arguments
                .iter()
                .map(|argument| evaluate(argument, values))
                .collect::<Option<_>>()?;
            // Python's min()/max(): the first of the extreme values.
            let wanted = if *is_min {
                Ordering::Less
            } else {
                Ordering::Greater
            };
            let mut best = found.first()?;
            for candidate in &found[1..] {
                if decimal::compare(candidate, best)? == wanted {
                    best = candidate;
                }
            }
            best.clone()
        }
        Node::Binary(op, left, right) => {
            let left = evaluate(left, values)?;
            let right = evaluate(right, values)?;
            match op {
                b'+' => decimal::add(&left, &right, false)?,
                b'-' => decimal::add(&left, &right, true)?,
                b'*' => decimal::mul(&left, &right)?,
                _ => {
                    if right.is_zero() {
                        return None;
                    }
                    decimal::div(&left, &right)?
                }
            }
        }
    };
    limited(result)
}
