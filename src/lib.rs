// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod abi;
mod encode;
#[cfg(target_arch = "wasm32")]
mod wasm;

use alloc::collections::{btree_map, BTreeMap};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use heck::{AsShoutySnekCase, AsUpperCamelCase};

use snafu::{ensure, Backtrace, Snafu};

use core::borrow::Borrow;
use core::fmt::{self, Write};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(context(false))]
    Abi {
        #[snafu(backtrace)]
        source: abi::Error,
    },

    #[cfg(feature = "std")]
    FileSystem {
        source: std::io::Error,
        path: std::path::PathBuf,
    },

    TypeCollision {
        backtrace: Backtrace,
        type_name: String,
    },
}

#[derive(Debug, Snafu)]
pub enum Warning {}

#[derive(Debug, Snafu)]
pub struct Locate<E>
where
    E: 'static + snafu::ErrorCompat + snafu::AsErrorSource + core::fmt::Display,
{
    #[snafu(backtrace, source)]
    inner: E,

    #[snafu(source(false))]
    source: String,
}

impl<E> Locate<E>
where
    E: 'static + snafu::ErrorCompat + snafu::AsErrorSource + core::fmt::Display,
{
    pub fn inner(&self) -> &E {
        &self.inner
    }

    pub fn into_inner(self) -> E {
        self.inner
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

pub trait Reporter {
    fn error(&mut self, _error: Locate<Error>) {}
    fn warning(&mut self, _warning: Locate<Warning>) {}
}

impl Reporter for () {}

trait IteratorExt: Iterator {
    type Output: Iterator<Item = Self::Item>;

    fn exclude_signature(self) -> Self::Output;
}

impl<T> IteratorExt for T
where
    T: Iterator,
    T::Item: Borrow<abi::Parameter>,
{
    type Output = core::iter::Filter<Self, fn(&T::Item) -> bool>;

    fn exclude_signature(self) -> Self::Output {
        self.filter(|i| match i.borrow().name() {
            "v" | "r" | "s" => false,
            _ => true,
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ChainId {
    WhenDeployed,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerifyingContract {
    This,
}

#[derive(Debug)]
pub struct Eip712<R> {
    reporter: R,
    source: Option<String>,
    functions: Vec<abi::Function>,
    parameters: BTreeMap<String, abi::Parameter>,

    base_contract: String,
    // TODO: License support.
    // TODO: Solidity version support.
    // TODO: Contract name support.
    signing_domain: Option<String>,
    version: Option<String>,
    chain_id: Option<ChainId>,
    verifying_contract: Option<VerifyingContract>,
    salt: Option<[u8; 32]>,
}

impl<R> Eip712<R>
where
    R: Default,
{
    pub fn new<B>(base_contract: B) -> Self
    where
        B: Into<String>,
    {
        let base_contract = base_contract.into();

        Self {
            reporter: Default::default(),
            source: None,
            functions: Default::default(),
            parameters: Default::default(),

            base_contract: base_contract.clone(),

            signing_domain: Some(base_contract),
            version: None,
            chain_id: Some(ChainId::WhenDeployed),
            verifying_contract: Some(VerifyingContract::This),
            salt: None,
        }
    }
}

impl<R> Eip712<R> {
    pub fn into_reporter(self) -> R {
        self.reporter
    }

    pub fn reporter(&self) -> &R {
        &self.reporter
    }

    pub fn reporter_mut(&mut self) -> &mut R {
        &mut self.reporter
    }

    pub fn clear_signing_domain(mut self) -> Self {
        self.signing_domain = None;
        self
    }

    pub fn signing_domain<S: Into<String>>(mut self, s: S) -> Self {
        self.signing_domain = Some(s.into());
        self
    }

    pub fn clear_version(mut self) -> Self {
        self.version = None;
        self
    }

    pub fn version<S: Into<String>>(mut self, s: S) -> Self {
        self.version = Some(s.into());
        self
    }

    pub fn clear_chain_id(mut self) -> Self {
        self.chain_id = None;
        self
    }

    pub fn chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    pub fn clear_verifying_contract(mut self) -> Self {
        self.verifying_contract = None;
        self
    }

    pub fn verifying_contract(mut self, vf: VerifyingContract) -> Self {
        self.verifying_contract = Some(vf);
        self
    }

    pub fn clear_salt(mut self) -> Self {
        self.salt = None;
        self
    }

    pub fn salt(mut self, s: [u8; 32]) -> Self {
        self.salt = Some(s);
        self
    }

    fn domain_separator_type(&self) -> abi::Parameter {
        let internal_kind = abi::InternalKind::new("struct EIP712.EIP712Domain".to_string());

        let mut components = Vec::with_capacity(5);

        if self.signing_domain.is_some() {
            let param = abi::Parameter::new(
                abi::InternalKind::string(),
                "name",
                abi::Kind::string(),
                Vec::new(),
            );
            components.push(param);
        }

        if self.version.is_some() {
            let param = abi::Parameter::new(
                abi::InternalKind::string(),
                "version",
                abi::Kind::string(),
                Vec::new(),
            );
            components.push(param);
        }

        if self.chain_id.is_some() {
            let param = abi::Parameter::new(
                abi::InternalKind::uint(256).unwrap(),
                "chainId",
                abi::Kind::uint(256).unwrap(),
                Vec::new(),
            );
            components.push(param);
        }

        if self.verifying_contract.is_some() {
            let param = abi::Parameter::new(
                abi::InternalKind::address(),
                "verifyingContract",
                abi::Kind::address(),
                Vec::new(),
            );
            components.push(param);
        }

        if self.salt.is_some() {
            let param = abi::Parameter::new(
                abi::InternalKind::bytes_sized(32).unwrap(),
                "salt",
                abi::Kind::bytes_sized(32).unwrap(),
                Vec::new(),
            );
            components.push(param);
        }

        abi::Parameter::new(
            internal_kind,
            "domain_separator",
            abi::Kind::tuple(),
            components,
        )
    }
}

impl<R> Eip712<R>
where
    R: Reporter,
{
    pub fn with_reporter<B>(base_contract: B, reporter: R) -> Self
    where
        B: Into<String>,
    {
        let base_contract = base_contract.into();

        Self {
            reporter,
            source: None,
            functions: Default::default(),
            parameters: Default::default(),

            base_contract: base_contract.clone(),

            signing_domain: Some(base_contract),
            version: None,
            chain_id: Some(ChainId::WhenDeployed),
            verifying_contract: Some(VerifyingContract::This),
            salt: None,
        }
    }

    #[must_use]
    fn require<T, E>(&mut self, result: Result<T, E>) -> Option<T>
    where
        E: snafu::Error + snafu::ErrorCompat + Into<Error>,
    {
        let inner = match result {
            Ok(v) => return Some(v),
            Err(e) => e.into(),
        };

        let wrapper = Locate {
            source: self.source.clone().unwrap_or_else(|| "<unknown>".into()),
            inner,
        };

        self.reporter.error(wrapper);

        None
    }

    fn match_inputs(entry: &abi::Function) -> bool {
        let mut v = false;
        let mut r = false;
        let mut s = false;

        for input in entry.inputs() {
            match input.name() {
                "v" if v => return false,
                "v" => v = true,

                "r" if r => return false,
                "r" => r = true,

                "s" if s => return false,
                "s" => s = true,

                _ => (),
            }
        }

        v & r & s
    }

    fn collect_functions(&mut self, entries: &[abi::Entry]) -> Option<Vec<abi::Function>> {
        let functions = entries
            .into_iter()
            .filter_map(abi::Entry::as_function)
            .filter(|e| Self::match_inputs(*e));

        // TODO: Warn if the implementation function (ie. _recover for recover)
        //       is visible in the ABI, since it must be internal.

        // TODO: Verify signature argument types (eg. v: uint8)

        Some(functions.cloned().collect())
    }

    fn collect_parameters(&self) -> Result<BTreeMap<String, abi::Parameter>, Error> {
        let mut parameters = BTreeMap::new();

        let mut todo: Vec<_> = self
            .functions
            .iter()
            .flat_map(abi::Function::inputs)
            .exclude_signature()
            .filter(|i| i.kind().base_kind() == abi::Kind::tuple())
            .collect();

        while let Some(input) = todo.pop() {
            if input.kind().base_kind() != abi::Kind::tuple() {
                continue;
            }

            let type_name = input.internal_kind().base_kind().shorten_kind();

            match parameters.entry(type_name.clone()) {
                btree_map::Entry::Vacant(v) => {
                    v.insert(input.clone());
                }
                btree_map::Entry::Occupied(o) => {
                    ensure!(o.get().eq_(input), TypeCollisionSnafu { type_name });
                    continue;
                }
            };

            for component in input.components() {
                todo.push(component);
            }
        }

        Ok(parameters)
    }

    fn read_inner(&mut self, entries: &[abi::Entry]) -> Option<()> {
        self.functions = self.collect_functions(entries)?;
        self.parameters = self.require(self.collect_parameters())?;

        Some(())
    }

    fn read(&mut self, entries: &[abi::Entry]) -> Option<&mut Self> {
        let r = self.read_inner(entries);
        self.source = None; // Always clear the source after reading.
        r.map(|()| self)
    }

    pub fn read_slice(&mut self, bytes: &[u8]) -> Option<&mut Self> {
        let entries = self.require(abi::from_slice(bytes))?;
        self.read(entries.as_slice())
    }

    #[cfg(feature = "std")]
    pub fn read_file<P>(&mut self, path: P) -> Option<&mut Self>
    where
        P: AsRef<std::path::Path>,
    {
        use snafu::ResultExt;

        use std::fs::File;

        let path = path.as_ref();

        if self.source.is_none() {
            self.source = Some(path.display().to_string());
        }

        let file = self.require(File::open(path).context(FileSystemSnafu { path: path }))?;

        let reader = std::io::BufReader::new(file);

        let entries = self.require(abi::from_reader(reader))?;
        self.read(entries.as_slice())
    }

    pub fn read_str(&mut self, text: &str) -> Option<&mut Self> {
        let entries = self.require(abi::from_str(text))?;
        self.read(entries.as_slice())
    }

    fn write_hash_struct<W>(mut w: W, parameter: &abi::Parameter) -> Result<(), fmt::Error>
    where
        W: Write,
    {
        write!(
            w,
            "hash{}",
            AsUpperCamelCase(parameter.internal_kind().shorten_kind())
        )
    }

    fn write_type_hash<W>(mut w: W, parameter: &abi::Parameter) -> Result<(), fmt::Error>
    where
        W: Write,
    {
        write!(
            w,
            "{}_TYPE_HASH",
            AsShoutySnekCase(parameter.internal_kind().shorten_kind())
        )
    }

    fn write_encode_data<W>(
        mut w: W,
        prefix: &str,
        parameter: &abi::Parameter,
    ) -> Result<(), fmt::Error>
    where
        W: Write,
    {
        writeln!(w, "        bytes memory buffer = abi.encodePacked(",)?;

        write!(w, "            ")?;

        Self::write_type_hash(&mut w, parameter)?;
        writeln!(w)?;

        writeln!(w, "        );")?;

        for component in parameter.components() {
            let mut source = format!("{}{}", prefix, component.name());
            let mut dest = "buffer".to_string();

            writeln!(w, "        {{")?;

            for (index, _) in component.internal_kind().array().iter().enumerate() {
                dest = format!("b{}", index);
                writeln!(w, "            bytes memory {};", dest)?;
                writeln!(
                    w,
                    "            for (uint a{0} = 0; a{0} < {1}.length; ++a{0}) {{",
                    index, source,
                )?;

                write!(source, "[a{}]", index).unwrap();
            }

            writeln!(w, "                {} = abi.encodePacked(", dest,)?;

            writeln!(w, "                    {},", dest,)?;

            match component.kind().base() {
                abi::Base::Tuple => {
                    write!(w, "                    ",)?;

                    Self::write_hash_struct(&mut w, component)?;

                    writeln!(w, "({})", source)?;
                }
                abi::Base::Bytes | abi::Base::String => {
                    writeln!(w, "                    keccak256(bytes({}))", source,)?
                }
                _ => writeln!(w, "                    abi.encode({})", source)?,
            }

            writeln!(w, "                );",)?;

            for (index, _) in component.internal_kind().array().iter().enumerate().rev() {
                writeln!(w, "            }}")?;

                let parent = match index {
                    0 => "buffer".to_string(),
                    _ => format!("b{}", index - 1),
                };

                writeln!(w, "            {} = abi.encodePacked(", parent,)?;
                writeln!(w, "                {},", parent,)?;
                writeln!(w, "                keccak256(b{})", index,)?;
                writeln!(w, "            );",)?;
            }

            writeln!(w, "        }}")?;
        }

        Ok(())
    }

    pub fn generate<W>(&self, mut w: W) -> Result<(), fmt::Error>
    where
        W: Write,
    {
        writeln!(w, "contract {}Impl is {0} {{", self.base_contract)?;

        for parameter in self.parameters.values() {
            write!(w, "    bytes32 constant private ")?;
            Self::write_type_hash(&mut w, parameter)?;
            writeln!(w, r#" = keccak256("{}");"#, encode::encode_type(parameter))?;

            write!(w, "    function ")?;

            Self::write_hash_struct(&mut w, parameter)?;

            writeln!(
                w,
                "({} calldata input712) private pure returns (bytes32) {{",
                parameter.internal_kind().shorten_kind(),
            )?;

            Self::write_encode_data(&mut w, "input712.", &parameter)?;

            writeln!(w, "        return keccak256(buffer);")?;
            writeln!(w, "    }}")?;
            writeln!(w)?;
        }

        writeln!(w)?;

        if self.chain_id.is_some() {
            writeln!(
                w,
                r#"    function chainId() private view returns (uint256 r) {{
        assembly {{ r := chainid() }}
    }}"#,
            )?;
            writeln!(w)?;
        }

        writeln!(
            w,
            r#"    bytes32 constant private DOMAIN_SEPARATOR_TYPE_HASH = keccak256("{}");"#,
            encode::encode_type(&self.domain_separator_type()),
        )?;

        writeln!(
            w,
            "    bytes32 immutable private DOMAIN_SEPARATOR = keccak256(abi.encode("
        )?;

        write!(w, "        DOMAIN_SEPARATOR_TYPE_HASH")?;

        if let Some(ref signing_domain) = self.signing_domain {
            writeln!(w, ",")?;
            write!(w, r#"        keccak256(bytes("{}"))"#, signing_domain)?;
        }

        if let Some(ref version) = self.version {
            writeln!(w, ",")?;
            write!(w, r#"        keccak256(bytes("{}"))"#, version)?;
        }

        if let Some(ref chain_id) = self.chain_id {
            match chain_id {
                ChainId::WhenDeployed => {
                    writeln!(w, ",")?;
                    write!(w, r#"        chainId()"#,)?;
                }
            }
        }

        if let Some(ref verifying_contract) = self.verifying_contract {
            match verifying_contract {
                VerifyingContract::This => {
                    writeln!(w, ",")?;
                    write!(w, r#"        address(this)"#)?;
                }
            }
        }

        if let Some(ref salt) = self.salt {
            writeln!(w, ",")?;
            write!(w, r#"        hex"{}""#, hex::encode(salt))?;
        }

        writeln!(w)?;
        writeln!(w, "    ));")?;

        for function in self.functions.iter() {
            let parameter = function.clone().into_input_parameter();

            write!(w, "    bytes32 constant private ")?;
            Self::write_type_hash(&mut w, &parameter)?;
            writeln!(w, r#" = keccak256("{}");"#, encode::encode_type(&parameter))?;

            writeln!(w, "    function {}(", function.name())?;

            let inputs = function.inputs();

            if inputs.len() > 1 {
                for input in &inputs[..inputs.len() - 1] {
                    write!(w, "        {}", input.internal_kind().shorten_kind(),)?;

                    if !input.kind().is_stack() {
                        write!(w, " calldata")?;
                    }

                    writeln!(w, " {},", input.name())?;
                }
            }

            if !inputs.is_empty() {
                let input = &inputs[inputs.len() - 1];
                writeln!(w, "        {} {}", input.internal_kind(), input.name())?;
            }

            writeln!(w, "    )")?;
            writeln!(w, "        public")?;

            match function.state_mutability() {
                abi::StateMutability::Nonpayable => (),
                m => writeln!(w, "        {}", m)?,
            }

            writeln!(w, "        override")?;

            let outputs = function.outputs();

            if !outputs.is_empty() {
                writeln!(w, "        returns (")?;

                for output in &outputs[..outputs.len() - 1] {
                    writeln!(w, "            {},", output.internal_kind())?;
                }

                writeln!(
                    w,
                    "            {}",
                    outputs[outputs.len() - 1].internal_kind()
                )?;

                writeln!(w, "        )")?;
            }

            writeln!(w, "    {{")?;

            Self::write_encode_data(&mut w, "", &parameter)?;

            writeln!(w, "        bytes32 message = keccak256(abi.encodePacked(",)?;

            writeln!(w, r#"            hex"1901","#,)?;

            writeln!(w, "            DOMAIN_SEPARATOR,",)?;

            writeln!(w, "            keccak256(buffer)",)?;

            writeln!(w, "        ));",)?;

            // TODO: Check for multiples of S or whatever that attack is.

            writeln!(w, "        address signer = ecrecover(message, v, r, s);",)?;

            writeln!(w, "        require(address(0) != signer);",)?;

            write!(w, "        return {}(signer", function.name(),)?;

            for input in function.inputs().iter().exclude_signature() {
                write!(w, ", {}", input.name(),)?;
            }

            writeln!(w, ");",)?;

            writeln!(w, "    }}")?;

            writeln!(w)?;
        }

        writeln!(w, "}}")?;

        Ok(())
    }

    pub fn source<S>(&mut self, source: S) -> &mut Self
    where
        S: Into<String>,
    {
        self.source = Some(source.into());
        self
    }
}
