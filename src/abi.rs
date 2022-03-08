// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Rust Representation of Solidity's [ABI].
//!
//! [ABI]: https://docs.soliditylang.org/en/v0.8.12/abi-spec.html

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::IteratorExt;

use heck::ToUpperCamelCase;

use serde::de::{Deserializer, Error as _};
use serde::{Deserialize, Serialize};

use smallvec::SmallVec;

use snafu::{Backtrace, OptionExt, ResultExt, Snafu};

use core::convert::TryFrom;
use core::fmt;
use core::num::NonZeroU32;
use core::str::FromStr;

/// Errors that can arise while parsing ABI descriptions.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    /// A problem with the input JSON (either the format itself, or its semantics.)
    Json {
        /// Underlying source of the error.
        source: JsonError,

        /// Location of the error.
        backtrace: Backtrace,
    },
}

/// Opaque wrapper type for JSON errors encountered while parsing ABI descriptions.
#[derive(Debug)]
pub struct JsonError(serde_json::Error);

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<serde_json::Error> for JsonError {
    fn from(e: serde_json::Error) -> Self {
        Self(e)
    }
}

impl snafu::Error for JsonError {}

/// Errors that can arise while parsing strings into [`Kind`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KindFromStrError {
    /// A portion of the string should have been a number, but wasn't.
    #[snafu(context(false))]
    ParseInt {
        /// Underlying source of the error.
        source: core::num::ParseIntError,

        /// Location of the error.
        backtrace: Backtrace,
    },

    /// A character wasn't valid in the input string.
    InvalidCharacter {
        /// Location of the error.
        backtrace: Backtrace,
    },

    /// The input string was shorter than expected (ex. an unclosed array type.)
    Truncated {
        /// Location of the error.
        backtrace: Backtrace,
    },

    /// The named type wasn't understood.
    UnknownKind {
        /// Location of the error.
        backtrace: Backtrace,
    },
}

/// Error that can arise while parsing strings into [`StateMutability`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub struct StateMutabilityFromStrError {}

/// Describes how state can be accessed by a function.
///
/// See: [State Mutability].
///
/// [State Mutability]: https://docs.soliditylang.org/en/v0.8.12/contracts.html#state-mutability
#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
#[serde(into = "String")]
pub enum StateMutability {
    /// Function does not read from or modify the state.
    ///
    /// See: [Pure Functions].
    ///
    /// [Pure Functions]: https://docs.soliditylang.org/en/v0.8.12/contracts.html#pure-functions
    Pure,

    /// Function may read from, but does not modify, the state.
    ///
    /// See: [View Functions].
    ///
    /// [View Functions]: https://docs.soliditylang.org/en/v0.8.12/contracts.html#view-functions
    View,

    /// Function may read and modify the state, but does not receive funds.
    Nonpayable,

    /// Function may read and modify the state, and may receive funds.
    Payable,
}

impl<'de> Deserialize<'de> for StateMutability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let txt = String::deserialize(deserializer)?;
        let obj = Self::from_str(&txt).map_err(D::Error::custom)?;
        Ok(obj)
    }
}

impl From<StateMutability> for String {
    fn from(s: StateMutability) -> Self {
        s.to_string()
    }
}

impl fmt::Display for StateMutability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let txt = match self {
            Self::Pure => "pure",
            Self::View => "view",
            Self::Nonpayable => "nonpayable",
            Self::Payable => "payable",
        };

        f.write_str(txt)
    }
}

impl FromStr for StateMutability {
    type Err = StateMutabilityFromStrError;

    fn from_str(txt: &str) -> Result<Self, Self::Err> {
        let result = match txt {
            "pure" => Self::Pure,
            "view" => Self::View,
            "nonpayable" => Self::Nonpayable,
            "payable" => Self::Payable,
            _ => return Err(StateMutabilityFromStrError {}),
        };

        Ok(result)
    }
}

impl TryFrom<&str> for StateMutability {
    type Error = StateMutabilityFromStrError;

    fn try_from(txt: &str) -> Result<Self, Self::Error> {
        txt.parse()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Base {
    Uint(u16),
    Int(u16),
    Address,
    Bool,
    Fixed(u16, u8),
    Ufixed(u16, u8),
    BytesSized(u8),
    Function,
    Bytes,
    String,
    Tuple,
}

impl Base {
    fn parse_fixed(txt: &str) -> Result<(u16, u8), KindFromStrError> {
        let (l, r) = txt.split_once('x').context(InvalidCharacterSnafu {})?;
        Ok((l.parse()?, r.parse()?))
    }
}

impl FromStr for Base {
    type Err = KindFromStrError;

    fn from_str(txt: &str) -> Result<Self, Self::Err> {
        match txt {
            "address" => return Ok(Base::Address),
            "bool" => return Ok(Base::Bool),
            "function" => return Ok(Base::Function),
            "bytes" => return Ok(Base::Bytes),
            "string" => return Ok(Base::String),
            "tuple" => return Ok(Base::Tuple),
            _ => (),
        }

        if let Some(num) = txt.strip_prefix("uint") {
            Ok(Self::Uint(num.parse()?))
        } else if let Some(num) = txt.strip_prefix("int") {
            Ok(Self::Int(num.parse()?))
        } else if let Some(f) = txt.strip_prefix("fixed") {
            let (l, r) = Self::parse_fixed(f)?;
            Ok(Self::Fixed(l, r))
        } else if let Some(f) = txt.strip_prefix("ufixed") {
            let (l, r) = Self::parse_fixed(f)?;
            Ok(Self::Ufixed(l, r))
        } else if let Some(num) = txt.strip_prefix("bytes") {
            Ok(Self::BytesSized(num.parse()?))
        } else {
            UnknownKindSnafu.fail()
        }
    }
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Uint(sz) => write!(f, "uint{}", sz),
            Self::Int(sz) => write!(f, "int{}", sz),
            Self::Address => write!(f, "address"),
            Self::Bool => write!(f, "bool"),
            Self::Fixed(l, r) => write!(f, "fixed{}x{}", l, r),
            Self::Ufixed(l, r) => write!(f, "ufixed{}x{}", l, r),
            Self::BytesSized(sz) => write!(f, "bytes{}", sz),
            Self::Function => write!(f, "function"),
            Self::Bytes => write!(f, "bytes"),
            Self::String => write!(f, "string"),
            Self::Tuple => write!(f, "tuple"),
        }
    }
}

/// Represents an array.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Array {
    /// Array with a fixed size: `uint8[5]`.
    Fixed(NonZeroU32),

    /// Array with a variable size: `uint8[]`.
    Variable,
}

/// Represents a Solidity type, like `uint256[98][][3]`.
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Hash)]
#[serde(into = "String")]
pub struct Kind {
    base: Base,
    array: SmallVec<[Array; 2]>,
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let txt = String::deserialize(deserializer)?;
        let obj = Self::from_str(&txt).map_err(D::Error::custom)?;
        Ok(obj)
    }
}

impl Kind {
    #[inline]
    pub(crate) fn is_stack(&self) -> bool {
        if !self.array.is_empty() {
            return false;
        }

        !matches!(self.base, Base::String | Base::Bytes | Base::Tuple)
    }

    #[inline]
    pub(crate) const fn base(&self) -> Base {
        self.base
    }

    /// This [`Kind`], but without any arrays.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind: Kind = "uint256[4][][4]".parse().unwrap();
    /// let base = kind.base_kind();
    ///
    /// assert_eq!(base.to_string(), "uint256");
    /// ```
    #[inline]
    pub const fn base_kind(&self) -> Self {
        Self {
            base: self.base,
            array: SmallVec::new_const(),
        }
    }

    /// Create a new [`Kind`] representing a Solidity `tuple`.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::tuple();
    ///
    /// assert_eq!(kind.to_string(), "tuple");
    /// ```
    #[inline]
    pub const fn tuple() -> Self {
        Self {
            base: Base::Tuple,
            array: SmallVec::new_const(),
        }
    }

    /// Create a new [`Kind`] representing an unsigned integer of size `sz`.
    ///
    /// Returns `None` if `sz` does not correspond to a valid Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::uint(32).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "uint32");
    /// ```
    #[inline]
    pub const fn uint(sz: u16) -> Option<Self> {
        if sz == 0 || sz > 256 || sz % 8 != 0 {
            None
        } else {
            Some(Self {
                base: Base::Uint(sz),
                array: SmallVec::new_const(),
            })
        }
    }

    /// Create a new [`Kind`] representing a signed integer of size `sz`.
    ///
    /// Returns `None` if `sz` does not correspond to a valid Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::int(32).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "int32");
    /// ```
    #[inline]
    pub const fn int(sz: u16) -> Option<Self> {
        if sz == 0 || sz > 256 || sz % 8 != 0 {
            None
        } else {
            Some(Self {
                base: Base::Int(sz),
                array: SmallVec::new_const(),
            })
        }
    }

    /// Create a new [`Kind`] representing a Solidity `address`.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::address();
    ///
    /// assert_eq!(kind.to_string(), "address");
    /// ```
    #[inline]
    pub const fn address() -> Self {
        Self {
            base: Base::Address,
            array: SmallVec::new_const(),
        }
    }

    /// Create a new [`Kind`] representing a Solidity `bool`.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::bool();
    ///
    /// assert_eq!(kind.to_string(), "bool");
    /// ```
    #[inline]
    pub const fn bool() -> Self {
        Self {
            base: Base::Bool,
            array: SmallVec::new_const(),
        }
    }

    /// Create a new [`Kind`] representing a Solidity signed fixed point number.
    ///
    /// Returns `None` if `m` and `n` do not correspond to a Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::fixed(8, 10).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "fixed8x10");
    /// ```
    #[inline]
    pub const fn fixed(m: u16, n: u8) -> Option<Self> {
        if 8 <= m && m <= 256 && m % 8 == 0 && 0 < n && n <= 80 {
            Some(Self {
                base: Base::Fixed(m, n),
                array: SmallVec::new_const(),
            })
        } else {
            None
        }
    }

    /// Create a new [`Kind`] representing a Solidity unsigned fixed point number.
    ///
    /// Returns `None` if `m` and `n` do not correspond to a Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::ufixed(8, 10).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "ufixed8x10");
    /// ```
    #[inline]
    pub const fn ufixed(m: u16, n: u8) -> Option<Self> {
        if 8 <= m && m <= 256 && m % 8 == 0 && 0 < n && n <= 80 {
            Some(Self {
                base: Base::Ufixed(m, n),
                array: SmallVec::new_const(),
            })
        } else {
            None
        }
    }

    /// Create a new [`Kind`] representing a fixed size bytes array (eg. `bytes32`.)
    ///
    /// Returns `None` if `sz` is zero or greater than 32.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::bytes_sized(32).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "bytes32");
    /// ```
    #[inline]
    pub const fn bytes_sized(sz: u8) -> Option<Self> {
        if sz == 0 || sz > 32 {
            None
        } else {
            Some(Self {
                base: Base::BytesSized(sz),
                array: SmallVec::new_const(),
            })
        }
    }

    /// Create a new [`Kind`] representing a Solidity function pointer.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::function();
    ///
    /// assert_eq!(kind.to_string(), "function");
    /// ```
    #[inline]
    pub const fn function() -> Self {
        Self {
            base: Base::Function,
            array: SmallVec::new_const(),
        }
    }

    /// Create a new [`Kind`] representing a variable size bytes array (`bytes`.)
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::bytes();
    ///
    /// assert_eq!(kind.to_string(), "bytes");
    /// ```
    #[inline]
    pub const fn bytes() -> Self {
        Self {
            base: Base::Bytes,
            array: SmallVec::new_const(),
        }
    }

    /// Create a new [`Kind`] representing a Solidity string.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::Kind;
    ///
    /// let kind = Kind::string();
    ///
    /// assert_eq!(kind.to_string(), "string");
    /// ```
    #[inline]
    pub const fn string() -> Self {
        Self {
            base: Base::String,
            array: SmallVec::new_const(),
        }
    }
}

impl TryFrom<InternalKind> for Kind {
    type Error = KindFromStrError;

    fn try_from(internal: InternalKind) -> Result<Self, Self::Error> {
        Ok(Self {
            base: internal.base.parse()?,
            array: internal.array,
        })
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.base)?;
        for array in self.array.iter() {
            match array {
                Array::Fixed(sz) => write!(f, "[{}]", sz)?,
                Array::Variable => write!(f, "[]")?,
            }
        }
        Ok(())
    }
}

impl From<Kind> for String {
    fn from(k: Kind) -> Self {
        k.to_string()
    }
}

fn parse_kind(txt: &str) -> Result<(&str, SmallVec<[Array; 2]>), KindFromStrError> {
    #[derive(Clone, Copy)]
    enum Mode {
        Base,
        Array(usize),
        Between,
    }

    let mut mode = Mode::Base;
    let mut base = txt;
    let mut array = SmallVec::new();

    for (idx, chr) in txt.char_indices() {
        match (mode, chr) {
            (Mode::Base, '[') => {
                base = &txt[..idx];
                mode = Mode::Array(idx);
            }
            (Mode::Base, c) if c.is_alphanumeric() => (),
            (Mode::Base, ' ') => (),
            (Mode::Base, '.') => (),
            (Mode::Base, _) => return InvalidCharacterSnafu.fail(),

            (Mode::Array(start), ']') => {
                let arr;
                if start == idx - 1 {
                    arr = Array::Variable;
                } else {
                    let num = txt[start + 1..idx].parse()?;
                    arr = Array::Fixed(num);
                }

                array.push(arr);
                mode = Mode::Between;
            }
            (Mode::Array(_), c) if c.is_numeric() => (),
            (Mode::Array(_), _) => return InvalidCharacterSnafu.fail(),

            (Mode::Between, '[') => mode = Mode::Array(idx),
            (Mode::Between, _) => return InvalidCharacterSnafu.fail(),
        }
    }

    match mode {
        Mode::Base | Mode::Between => (),
        _ => return TruncatedSnafu.fail(),
    }

    Ok((base, array))
}

impl FromStr for Kind {
    type Err = KindFromStrError;

    fn from_str(txt: &str) -> Result<Self, Self::Err> {
        let (base, array) = parse_kind(txt)?;

        Ok(Self {
            base: base.parse()?,
            array,
        })
    }
}

impl TryFrom<&str> for Kind {
    type Error = KindFromStrError;

    fn try_from(txt: &str) -> Result<Self, Self::Error> {
        txt.parse()
    }
}

/// Represents a user-defined Solidity type, like `struct Foo.Bar[][4]`.
#[derive(Debug, Serialize, Clone, Eq, PartialEq)]
#[serde(into = "String")]
pub struct InternalKind {
    base: String,
    array: SmallVec<[Array; 2]>,
}

impl<'de> Deserialize<'de> for InternalKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let txt = String::deserialize(deserializer)?;
        let obj = Self::from_str(&txt).map_err(D::Error::custom)?;
        Ok(obj)
    }
}

impl InternalKind {
    #[inline]
    pub(crate) fn new(base: String) -> Self {
        Self {
            base,
            array: SmallVec::new_const(),
        }
    }

    #[inline]
    pub(crate) fn shorten_kind(&self) -> String {
        let text = self.to_string();

        text.rsplit_once('.')
            .map(|(_, e)| e.to_string())
            .unwrap_or(text)
    }

    /// This [`InternalKind`], but without any arrays.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind: InternalKind = "struct Foo.Bar[4][][4]".parse().unwrap();
    /// let base = kind.base_kind();
    ///
    /// assert_eq!(base.to_string(), "struct Foo.Bar");
    /// ```
    #[inline]
    pub fn base_kind(&self) -> Self {
        Self {
            base: self.base.clone(),
            array: SmallVec::new_const(),
        }
    }

    /// String representation of the base type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind: InternalKind = "struct Foo.Bar[4][][4]".parse().unwrap();
    /// let base = kind.base();
    ///
    /// assert_eq!(base, "struct Foo.Bar");
    /// ```
    #[inline]
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Array component.
    ///
    /// ## Example
    ///
    /// ```
    /// use core::num::NonZeroU32;
    ///
    /// use eip712::abi::InternalKind;
    /// use eip712::abi::Array::*;
    ///
    /// let kind: InternalKind = "struct Foo.Bar[4][][4]".parse().unwrap();
    /// let array = kind.array();
    ///
    /// let four = NonZeroU32::new(4).unwrap();
    ///
    /// assert_eq!(array, [Fixed(four), Variable, Fixed(four)]);
    /// ```
    #[inline]
    pub fn array(&self) -> &[Array] {
        &self.array
    }

    /// Create a new [`InternalKind`] representing an unsigned integer of size `sz`.
    ///
    /// Returns `None` if `sz` does not correspond to a valid Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::uint(32).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "uint32");
    /// ```
    #[inline]
    pub fn uint(sz: u16) -> Option<Self> {
        Kind::uint(sz).map(Into::into)
    }

    /// Create a new [`InternalKind`] representing a signed integer of size `sz`.
    ///
    /// Returns `None` if `sz` does not correspond to a valid Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::int(32).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "int32");
    /// ```
    #[inline]
    pub fn int(sz: u16) -> Option<Self> {
        Kind::int(sz).map(Into::into)
    }

    /// Create a new [`InternalKind`] representing a Solidity `address`.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::address();
    ///
    /// assert_eq!(kind.to_string(), "address");
    /// ```
    #[inline]
    pub fn address() -> Self {
        Kind::address().into()
    }

    /// Create a new [`InternalKind`] representing a Solidity `bool`.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::bool();
    ///
    /// assert_eq!(kind.to_string(), "bool");
    /// ```
    #[inline]
    pub fn bool() -> Self {
        Kind::bool().into()
    }

    /// Create a new [`InternalKind`] representing a Solidity signed fixed point number.
    ///
    /// Returns `None` if `m` and `n` do not correspond to a Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::fixed(8, 10).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "fixed8x10");
    /// ```
    #[inline]
    pub fn fixed(m: u16, n: u8) -> Option<Self> {
        Kind::fixed(m, n).map(Into::into)
    }

    /// Create a new [`InternalKind`] representing a Solidity unsigned fixed point number.
    ///
    /// Returns `None` if `m` and `n` do not correspond to a Solidity type.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::ufixed(8, 10).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "ufixed8x10");
    /// ```
    #[inline]
    pub fn ufixed(m: u16, n: u8) -> Option<Self> {
        Kind::ufixed(m, n).map(Into::into)
    }

    /// Create a new [`InternalKind`] representing a fixed size bytes array (eg. `bytes32`.)
    ///
    /// Returns `None` if `sz` is zero or greater than 32.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::bytes_sized(32).unwrap();
    ///
    /// assert_eq!(kind.to_string(), "bytes32");
    /// ```
    #[inline]
    pub fn bytes_sized(sz: u8) -> Option<Self> {
        Kind::bytes_sized(sz).map(Into::into)
    }

    /// Create a new [`InternalKind`] representing a Solidity function pointer.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::function();
    ///
    /// assert_eq!(kind.to_string(), "function");
    /// ```
    #[inline]
    pub fn function() -> Self {
        Kind::function().into()
    }

    /// Create a new [`InternalKind`] representing a variable size bytes array (`bytes`.)
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::bytes();
    ///
    /// assert_eq!(kind.to_string(), "bytes");
    /// ```
    #[inline]
    pub fn bytes() -> Self {
        Kind::bytes().into()
    }

    /// Create a new [`InternalKind`] representing a Solidity string.
    ///
    /// ## Example
    ///
    /// ```
    /// use eip712::abi::InternalKind;
    ///
    /// let kind = InternalKind::string();
    ///
    /// assert_eq!(kind.to_string(), "string");
    /// ```
    #[inline]
    pub fn string() -> Self {
        Kind::string().into()
    }
}

impl TryFrom<&str> for InternalKind {
    type Error = KindFromStrError;

    fn try_from(txt: &str) -> Result<Self, Self::Error> {
        txt.parse()
    }
}

impl From<Kind> for InternalKind {
    fn from(kind: Kind) -> Self {
        Self {
            base: kind.base.to_string(),
            array: kind.array,
        }
    }
}

impl FromStr for InternalKind {
    type Err = KindFromStrError;

    fn from_str(txt: &str) -> Result<Self, Self::Err> {
        let (base, array) = parse_kind(txt)?;

        Ok(Self {
            base: base.to_string(),
            array,
        })
    }
}

impl fmt::Display for InternalKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.base)?;
        for array in self.array.iter() {
            match array {
                Array::Fixed(sz) => write!(f, "[{}]", sz)?,
                Array::Variable => write!(f, "[]")?,
            }
        }
        Ok(())
    }
}

impl From<InternalKind> for String {
    fn from(k: InternalKind) -> Self {
        k.to_string()
    }
}

/// Description of an input or output parameter.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Parameter {
    #[serde(rename = "internalType")]
    internal_kind: InternalKind,

    name: String,

    #[serde(rename = "type")]
    kind: Kind,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    components: Vec<Self>,
}

impl Parameter {
    pub(super) fn new<S: Into<String>>(
        internal_kind: InternalKind,
        name: S,
        kind: Kind,
        components: Vec<Self>,
    ) -> Self {
        Self {
            internal_kind,
            name: name.into(),
            kind,
            components,
        }
    }

    /// Internal type of this parameter.
    ///
    /// This is where information about structs and other complex data types can
    /// be found.
    #[inline]
    pub fn internal_kind(&self) -> &InternalKind {
        &self.internal_kind
    }

    /// Name of this parameter.
    ///
    /// In functions, this is the name of the parameter itself. In structs, this
    /// is the field name.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Actual ABI type of this parameter.
    ///
    /// For structs, this will be `tuple`.
    #[inline]
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// For complex data types, the parameters that describe the structure of this
    /// parameter.
    #[inline]
    pub fn components(&self) -> &[Self] {
        &self.components
    }

    /// Compare this parameter with `other`, ignoring the names of fields.
    #[inline]
    pub fn eq_(&self, other: &Self) -> bool {
        if self.internal_kind != other.internal_kind {
            return false;
        }

        if self.components.len() != other.components.len() {
            return false;
        }

        for (mine, theirs) in self.components.iter().zip(other.components.iter()) {
            if !mine.eq_(theirs) {
                return false;
            }
        }

        true
    }
}

/// Description of a function exposed in the ABI.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    inputs: Vec<Parameter>,
    outputs: Vec<Parameter>,
    name: String,
    state_mutability: StateMutability,
}

impl Function {
    /// Parameters this function accepts as arguments.
    #[inline]
    pub fn inputs(&self) -> &[Parameter] {
        self.inputs.as_slice()
    }

    /// Parameters this function returns.
    #[inline]
    pub fn outputs(&self) -> &[Parameter] {
        self.outputs.as_slice()
    }

    /// Name of this function.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Description of how this function may modify state.
    #[inline]
    pub fn state_mutability(&self) -> StateMutability {
        self.state_mutability
    }

    #[inline]
    pub(crate) fn into_input_parameter(self) -> Parameter {
        let name = self.name.to_upper_camel_case();

        Parameter {
            components: self.inputs.into_iter().exclude_signature().collect(),
            internal_kind: InternalKind {
                base: format!("struct Fn.{}", name),
                array: SmallVec::new_const(),
            },
            name,
            kind: Kind::tuple(),
        }
    }
}

/// Description of an argument to an event.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EventParameter {
    indexed: bool,

    #[serde(flatten)]
    parameter: Parameter,
}

impl EventParameter {
    /// Whether this event parameter is included as part of the topic.
    pub fn indexed(&self) -> bool {
        self.indexed
    }

    /// Internal type of this event parameter.
    ///
    /// Includes information about structs and other complex types.
    pub fn internal_kind(&self) -> &InternalKind {
        &self.parameter.internal_kind
    }

    /// Name of this event parameter.
    pub fn name(&self) -> &str {
        &self.parameter.name
    }

    /// Actual type of this event parameter.
    pub fn kind(&self) -> &Kind {
        &self.parameter.kind
    }

    /// For complex data types, the parameters that describe the structure of this
    /// event parameter.
    pub fn components(&self) -> &[Parameter] {
        &self.parameter.components
    }
}

/// Description of an event specified by an ABI.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    anonymous: bool,
    inputs: Vec<EventParameter>,
    name: String,
}

impl Event {
    /// False if this event has a name, true otherwise.
    #[inline]
    pub fn anonymous(&self) -> bool {
        self.anonymous
    }

    /// Parameters captured by this event.
    #[inline]
    pub fn inputs(&self) -> &[EventParameter] {
        self.inputs.as_slice()
    }

    /// Name of this event.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// An ABI item.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum Entry {
    /// Function described by the ABI.
    Function(Function),

    /// Event described by the ABI.
    Event(Event),
}

impl Entry {
    /// If this entry is an event, return it. Otherwise return `None`.
    pub fn as_event(&self) -> Option<&Event> {
        match self {
            Self::Event(e) => Some(e),
            Self::Function(_) => None,
        }
    }

    /// If this entry is an event, return it. Otherwise panic.
    pub fn unwrap_event(self) -> Event {
        match self {
            Self::Event(e) => e,
            Self::Function(_) => panic!("not event"),
        }
    }

    /// If this entry is function, return it. Otherwise return `None`.
    pub fn as_function(&self) -> Option<&Function> {
        match self {
            Self::Function(f) => Some(f),
            Self::Event(_) => None,
        }
    }

    /// If this entry is function, return it. Otherwise panic.
    pub fn unwrap_function(self) -> Function {
        match self {
            Self::Function(f) => f,
            Self::Event(_) => panic!("not function"),
        }
    }
}

/// Parse an ABI description from text.
pub fn from_str(text: &str) -> Result<Vec<Entry>, Error> {
    let result = serde_json::from_str(text)
        .map_err(JsonError::from)
        .context(JsonSnafu)?;
    Ok(result)
}

/// Parse an ABI description from a reader.
#[cfg(feature = "std")]
pub fn from_reader<R>(reader: R) -> Result<Vec<Entry>, Error>
where
    R: std::io::Read,
{
    let result = serde_json::from_reader(reader)
        .map_err(JsonError::from)
        .context(JsonSnafu)?;
    Ok(result)
}

/// Parse an ABI description from a byte slice.
pub fn from_slice(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    let result = serde_json::from_slice(bytes)
        .map_err(JsonError::from)
        .context(JsonSnafu)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[crate::test]
    fn parse_uint32() {
        let input = "uint32";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Uint(32),
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_uint() {
        let input = "uint";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_int32() {
        let input = "int32";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Int(32),
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_int() {
        let input = "int";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_address() {
        let input = "address";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Address,
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_addr() {
        let input = "addr";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_bool() {
        let input = "bool";
        input.parse::<Kind>().unwrap();
    }

    #[crate::test]
    fn parse_bool1() {
        let input = "bool1";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_fixed8x1() {
        let input = "fixed8x1";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Fixed(8, 1),
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_fixed8x1x1() {
        let input = "fixed8x1x1";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_ufixed8x1() {
        let input = "ufixed8x1";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Ufixed(8, 1),
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_ufixed8x1x1() {
        let input = "ufixed8x1x1";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_bytes12() {
        let input = "bytes12";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::BytesSized(12),
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_bytes12x1() {
        let input = "bytes12x1";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_function() {
        let input = "function";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Function,
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_functionx1() {
        let input = "functionx1";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_string() {
        let input = "string";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::String,
            array: SmallVec::new(),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_stringx1() {
        let input = "stringx1";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_uint32_array() {
        let input = "uint32[]";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Uint(32),
            array: From::from(&[Array::Variable] as &[_]),
        };

        assert_eq!(actual, expected);
    }

    #[crate::test]
    fn parse_uint32_array_unclosed() {
        let input = "uint32[";
        input.parse::<Kind>().unwrap_err();
    }

    #[crate::test]
    fn parse_uint32_array_sized() {
        let input = "uint32[3422]";
        let actual: Kind = input.parse().unwrap();
        let expected = Kind {
            base: Base::Uint(32),
            array: From::from(&[Array::Fixed(3422.try_into().unwrap())] as &[_]),
        };

        assert_eq!(actual, expected);
    }
}
