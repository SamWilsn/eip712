// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! # eip712
//!
//! [EIP-712] is a standard for signing structured data in the Ethereum
//! ecosystem. This crate is a tool for generating Solidity code for verifying
//! [EIP-712] style signatures based on a JSON description of a contract's
//! [ABI].
//!
//!
//! [EIP-712]: https://eips.ethereum.org/EIPS/eip-712
//! [ABI]: https://docs.soliditylang.org/en/v0.8.12/abi-spec.html
//!
//! ## Features
//!
//! This crate has a couple optional features:
//!
//!  - `backtraces`: Collect backtraces on error types.
//!  - `std`: Use the Rust standard library.
//!
//! ## Example
//!
//! See [`Eip712`] for an example.

use alloc::string::{String, ToString};

use crate::{Error, Locate, Warning};

use js_sys::{Array, Function};

use wasm_bindgen::prelude::*;

#[derive(Debug, Default)]
struct Reporter {
    error: Option<Function>,
    warning: Option<Function>,
}

impl crate::Reporter for Reporter {
    fn error(&mut self, error: Locate<Error>) {
        if let Some(ref mut handler) = self.error.as_mut() {
            handler
                .apply(
                    &JsValue::NULL,
                    &Array::of1(&JsValue::from_str(&error.inner().to_string())),
                )
                .ok();
        }
    }

    fn warning(&mut self, warn: Locate<Warning>) {
        if let Some(ref mut handler) = self.warning.as_mut() {
            handler
                .apply(
                    &JsValue::NULL,
                    &Array::of1(&JsValue::from_str(&warn.inner().to_string())),
                )
                .ok();
        }
    }
}

#[derive(Debug)]
#[wasm_bindgen]
pub struct Eip712(crate::Eip712<Reporter>);

#[wasm_bindgen]
impl Eip712 {
    /// Create a new `Eip712` instance, to extend `base_contract`.
    ///
    /// `Eip712` generates a concrete implementation for abstract methods
    /// specified in an ABI. Since the ABI lacks the actual name of the contract,
    /// it must be provided in `base_contract`.
    ///
    /// ## Example
    ///
    /// ```javascript
    /// import { default as eip712, Eip712 } from './eip712.js';
    ///
    /// async function main() {
    ///     await eip712();
    ///
    ///     // Read the ABI file (normally generated by `solc`.)
    ///     const resp = await fetch("./NameRegistry.json");
    ///     const abi = await resp.text();
    ///
    ///     // Configure and run the generator.
    ///     const output = new Eip712("NameRegistry")   // Name of the base contract.
    ///         .error(console.log)                     // Error handler.
    ///         .warning(console.log)                   // Warning handler.
    ///         .signing_domain("NameRegistry")         // Name for the EIP-712 domain.
    ///         .version("1")                           // Contract version.
    ///         .read_str(abi)
    ///         .generate();
    ///
    ///     let elem = document.createElement('pre');
    ///     elem.innerText = output;
    ///     document.body.appendChild(elem);
    /// }
    ///
    /// main();
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(base_contract: String) -> Self {
        Self(crate::Eip712::new(base_contract))
    }

    /// Set the handler for error-level messages.
    pub fn error(mut self, handler: Function) -> Self {
        self.0.reporter_mut().error = Some(handler);
        self
    }

    /// Set the handler for warning-level messages.
    pub fn warning(mut self, handler: Function) -> Self {
        self.0.reporter_mut().warning = Some(handler);
        self
    }

    /// Remove the `name` field from the domain separator.
    pub fn clear_signing_domain(self) -> Self {
        Self(self.0.clear_signing_domain())
    }

    /// Include the given value as the user readable `name` field in the domain
    /// separator.
    pub fn signing_domain(self, s: String) -> Self {
        Self(self.0.signing_domain(s))
    }

    /// Remove the `version` field from the domain separator.
    pub fn clear_version(self) -> Self {
        Self(self.0.clear_version())
    }

    /// Include the given value as the `version` field in the domain separator.
    pub fn version(self, s: String) -> Self {
        Self(self.0.version(s))
    }

    /// Remove the `chainId` field from the domain separator.
    pub fn clear_chain_id(self) -> Self {
        Self(self.0.clear_chain_id())
    }

    /*
    // TODO: Figure out how to represent ChainId
    pub fn chain_id(self, chain_id: ChainId) -> Self {
        self.chain_id = Some(chain_id);
        self
    }
    */

    /// Remove the `verifyingContract` field from the domain separator.
    pub fn clear_verifying_contract(self) -> Self {
        Self(self.0.clear_verifying_contract())
    }

    /*
    // TODO: Figure out how to represent VerifyingContract.
    pub fn verifying_contract(self, vf: VerifyingContract) -> Self {
        self.verifying_contract = Some(vf);
        self
    }
    */

    /// Remove the `salt` field from the domain separator.
    pub fn clear_salt(self) -> Self {
        Self(self.0.clear_salt())
    }

    /// Include the given value as the `salt` field in the domain separator.
    pub fn salt(self, s: &[u8]) -> Self {
        Self(self.0.salt(s.try_into().unwrap()))
    }

    /// Read an ABI description from a string slice.
    pub fn read_str(self, text: &str) -> Option<Eip712> {
        self.0.read_str(text).map(Self)
    }

    /// Generate the implementation and return it as a string.
    pub fn generate(self) -> Option<String> {
        let mut out = String::new();
        self.0.generate(&mut out).unwrap();
        Some(out)
    }

    /// Set the name of the source.
    pub fn source(mut self, source: String) -> Self {
        self.0.source(source);
        self
    }
}
