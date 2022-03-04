// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use eip712::{Eip712, Error, Locate, Warning};

use std::io::Write;

#[derive(Default)]
struct ConsoleReporter;

impl eip712::Reporter for ConsoleReporter {
    fn error(&mut self, error: Locate<Error>) {
        eprintln!("ERROR: {:#?}", error);
    }

    fn warning(&mut self, error: Locate<Warning>) {
        eprintln!("WARN: {:#?}", error);
    }
}

fn main() {
    let abi = include_str!("../../tests/abi/arraystruct.json");
    let mut output = String::new();

    Eip712::<ConsoleReporter>::new("ArrayInStruct")
        .signing_domain("ArrayInStruct")
        .version("1")
        .read_str(abi)
        .unwrap()
        .generate(&mut output)
        .unwrap();

    std::io::stdout().write_all(output.as_bytes()).unwrap();
}
