// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use clap::{ArgEnum, Parser};

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

#[derive(Debug, Clone, ArgEnum)]
enum VerifyingContract {
    This,
}

#[derive(Debug, Parser)]
struct Args {
    source: PathBuf,

    #[clap(short, long)]
    base: String,

    #[clap(short, long)]
    version: Option<String>,

    #[clap(short('n'), long)]
    signing_domain: Option<String>,

    #[clap(long)]
    no_verifying_contract: bool,

    #[clap(long)]
    no_chain_id: bool,

    #[clap(long)]
    salt: Option<Salt>,

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
