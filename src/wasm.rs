// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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

#[wasm_bindgen]
pub struct Eip712(crate::Eip712<Reporter>);

#[wasm_bindgen]
impl Eip712 {
    #[wasm_bindgen(constructor)]
    pub fn new(base_contract: String) -> Self {
        Self(crate::Eip712::new(base_contract))
    }

    pub fn error(mut self, handler: Function) -> Self {
        self.0.reporter_mut().error = Some(handler);
        self
    }

    pub fn warning(mut self, handler: Function) -> Self {
        self.0.reporter_mut().warning = Some(handler);
        self
    }

    pub fn clear_signing_domain(self) -> Self {
        Self(self.0.clear_signing_domain())
    }

    pub fn signing_domain(self, s: String) -> Self {
        Self(self.0.signing_domain(s))
    }

    pub fn clear_version(self) -> Self {
        Self(self.0.clear_version())
    }

    pub fn version(self, s: String) -> Self {
        Self(self.0.version(s))
    }

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

    pub fn clear_salt(self) -> Self {
        Self(self.0.clear_salt())
    }

    pub fn salt(self, s: &[u8]) -> Self {
        Self(self.0.salt(s.try_into().unwrap()))
    }

    pub fn read_str(mut self, text: &str) -> Option<Eip712> {
        match self.0.read_str(text) {
            Some(_) => Some(self),
            None => None,
        }
    }

    pub fn generate(self) -> Option<String> {
        let mut out = String::new();
        self.0.generate(&mut out).unwrap();
        Some(out)
    }
}
