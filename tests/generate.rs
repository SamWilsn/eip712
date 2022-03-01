// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use eip712::Eip712;

#[test]
fn simple() {
    let abi = include_str!("abi/simple.json");
    let mut actual = String::new();

    Eip712::<()>::new("Simple")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"contract SimpleImpl is Simple {
    bytes32 constant public NONPAYABLE_BARE_DOMAIN_SEPARATOR = ;
    function nonpayableBare(
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        override
    {
    }

    bytes32 constant public PAYABLE_TWO_RETURNS_DOMAIN_SEPARATOR = ;
    function payableTwoReturns(
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        payable
        override
        returns (
            uint8,
            uint256
        )
    {
    }

    bytes32 constant public VIEW_ONE_ARG_DOMAIN_SEPARATOR = ;
    function viewOneArg(
        uint256 hello,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        view
        override
    {
    }

}
"#;

    assert_eq!(actual, expected);
}

#[test]
fn level1() {
    let abi = include_str!("abi/level1.json");
    let mut actual = String::new();

    Eip712::<()>::new("Level1")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"
"#;

    assert_eq!(actual, expected);
}

#[test]
fn level2() {
    let abi = include_str!("abi/level2.json");
    let mut actual = String::new();

    Eip712::<()>::new("Level2")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"
"#;

    assert_eq!(actual, expected);
}

#[test]
fn array_in_struct() {
    let abi = include_str!("abi/arraystruct.json");
    let mut actual = String::new();

    Eip712::<()>::new("ArrayInStruct")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"
"#;

    assert_eq!(actual, expected);
}
