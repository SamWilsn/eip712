// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use eip712::abi::{self, Kind, StateMutability};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn ownable() {
    let ownable = abi::from_slice(include_bytes!("abi/ownable.json")).unwrap();
    assert_eq!(4, ownable.len());

    // event OwnershipTransferred(address previousOwner, address newOwner)
    let event = ownable[0].as_event().unwrap();
    assert_eq!(false, event.anonymous());
    assert_eq!("OwnershipTransferred", event.name());

    let inputs = event.inputs();
    assert_eq!(2, inputs.len());

    assert_eq!(true, inputs[0].indexed());
    assert_eq!(
        Kind::address(),
        inputs[0].internal_kind().clone().try_into().unwrap()
    );
    assert_eq!("previousOwner", inputs[0].name());
    assert_eq!(&Kind::address(), inputs[0].kind());

    assert_eq!(true, inputs[1].indexed());
    assert_eq!(
        Kind::address(),
        inputs[1].internal_kind().clone().try_into().unwrap()
    );
    assert_eq!("newOwner", inputs[1].name());
    assert_eq!(&Kind::address(), inputs[1].kind());

    //
    // function owner()
    //
    let func = ownable[1].as_function().unwrap();
    assert_eq!("owner", func.name());
    assert_eq!(StateMutability::View, func.state_mutability());

    assert!(func.inputs().is_empty());

    let outputs = func.outputs();
    assert_eq!(1, outputs.len());

    assert_eq!(
        Kind::address(),
        outputs[0].internal_kind().clone().try_into().unwrap()
    );
    assert_eq!("", outputs[0].name());
    assert_eq!(&Kind::address(), outputs[0].kind());

    //
    // function renounceOwnership()
    //
    let func = ownable[2].as_function().unwrap();
    assert_eq!("renounceOwnership", func.name());
    assert_eq!(StateMutability::Nonpayable, func.state_mutability());

    assert!(func.inputs().is_empty());
    assert!(func.outputs().is_empty());

    //
    // function transferOwnership(address newOwner)
    //
    let func = ownable[3].as_function().unwrap();
    assert_eq!("transferOwnership", func.name());
    assert_eq!(StateMutability::Nonpayable, func.state_mutability());

    assert!(func.outputs().is_empty());

    let inputs = func.inputs();
    assert_eq!(1, inputs.len());

    assert_eq!(
        Kind::address(),
        inputs[0].internal_kind().clone().try_into().unwrap()
    );
    assert_eq!("newOwner", inputs[0].name());
    assert_eq!(&Kind::address(), inputs[0].kind());
}

const FOO: &[u8] = include_bytes!("abi/foo.json");

#[test]
fn foo() {
    let foo = abi::from_slice(FOO).unwrap();
    assert_eq!(3, foo.len());

    // TODO
}

#[test]
fn foo_to_foo() {
    let expected: serde_json::Value = serde_json::from_slice(FOO).unwrap();

    let foo = abi::from_slice(FOO).unwrap();
    let actual = serde_json::to_value(foo).unwrap();

    if expected != actual {
        println!("Expected:");
        println!("{:#}", expected);
        println!();
        println!("Actual:");
        println!("{:#}", actual);
    }

    assert_eq!(expected, actual);
}
