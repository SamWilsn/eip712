// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use clap::Parser;

use eip712::{Eip712, Error, Locate, Warning};

use snafu::{Backtrace, ErrorCompat, OptionExt, Snafu};

use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Snafu)]
enum SaltFromStrError {
    /// Hex prefix (`0x`) not present.
    MissingPrefix,

    #[snafu(context(false))]
    Hex {
        source: hex::FromHexError,
        backtrace: Backtrace,
    },
}

#[derive(Debug)]
struct Salt([u8; 32]);

impl FromStr for Salt {
    type Err = SaltFromStrError;

    fn from_str(txt: &str) -> Result<Self, Self::Err> {
        let txt = txt.strip_prefix("0x").context(MissingPrefixSnafu)?;
        let mut array = [0; 32];
        hex::decode_to_slice(txt, &mut array)?;
        Ok(Self(array))
    }
}

/// Generate Solidity for verifying EIP-712 style signatures.
#[derive(Debug, Parser)]
struct Args {
    /// Path to the ABI description as JSON.
    source: PathBuf,

    /// Name of the contract to inherit from.
    #[clap(short, long, display_order(1))]
    base: String,

    /// Optional version to use in domain separator.
    #[clap(short, long, help_heading("DOMAIN SEPARATOR"))]
    version: Option<String>,

    /// Do not use a name in the domain separator.
    #[clap(
        long,
        conflicts_with("signing-domain"),
        display_order(2),
        help_heading("DOMAIN SEPARATOR")
    )]
    no_signing_domain: bool,

    /// Optional name to use in domain separator.
    #[clap(
        short('n'),
        value_name("NAME"),
        long,
        display_order(2),
        help_heading("DOMAIN SEPARATOR")
    )]
    signing_domain: Option<String>,

    /// Do not include verifying contract in domain separator.
    #[clap(long, help_heading("DOMAIN SEPARATOR"))]
    no_verifying_contract: bool,

    /// Do not include chain ID in domain separator.
    #[clap(long, help_heading("DOMAIN SEPARATOR"))]
    no_chain_id: bool,

    /// Optional salt to use in domain separator.
    #[clap(short, long, help_heading("DOMAIN SEPARATOR"))]
    salt: Option<Salt>,

    /// Path to write the output Solidity to.
    #[clap(short, long)]
    output: Option<PathBuf>,
}

#[derive(Default)]
struct ConsoleReporter;

impl ConsoleReporter {
    fn report<I>(e: I)
    where
        I: 'static + snafu::Error + ErrorCompat,
    {
        eprintln!("{}", e);

        #[cfg(feature = "backtraces")]
        if let Some(bt) = ErrorCompat::backtrace(&e) {
            eprintln!("{}", bt);
        }

        for item in ErrorCompat::iter_chain(&e).skip(1) {
            eprintln!();
            eprintln!("--- Caused by:");
            eprintln!();

            eprintln!("{}", item);
        }
    }
}

impl eip712::Reporter for ConsoleReporter {
    fn error(&mut self, error: Locate<Error>) {
        eprint!("ERROR ({}): ", error.source());
        Self::report(error.into_inner());
    }

    fn warning(&mut self, warning: Locate<Warning>) {
        eprint!("WARN ({}): ", warning.source());
        Self::report(warning.into_inner());
    }
}

fn run() -> Option<()> {
    let args = Args::parse();

    let mut gen = Eip712::<ConsoleReporter>::new(&args.base);

    if let Some(version) = args.version {
        gen = gen.version(version);
    }

    if args.no_signing_domain {
        gen = gen.clear_signing_domain();
    }

    if let Some(signing_domain) = args.signing_domain {
        gen = gen.signing_domain(signing_domain);
    }

    if args.no_verifying_contract {
        gen = gen.clear_verifying_contract();
    }

    if args.no_chain_id {
        gen = gen.clear_chain_id();
    }

    if let Some(salt) = args.salt {
        gen = gen.salt(salt.0);
    }

    let mut output = String::new();

    gen.read_file(args.source)?.generate(&mut output).unwrap();

    match args.output {
        Some(s) => std::fs::write(s, output).unwrap(),
        None => std::io::stdout().write_all(output.as_bytes()).unwrap(),
    }

    Some(())
}

fn main() {
    match run() {
        None => std::process::exit(1),
        Some(_) => (),
    }
}
