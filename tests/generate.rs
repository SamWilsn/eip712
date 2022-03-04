// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// TODO: Verify that the generated solidity works!

use eip712::Eip712;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn simple() {
    let abi = include_str!("abi/simple.json");
    let mut actual = String::new();

    Eip712::<()>::new("Simple")
        .version("1")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"contract SimpleImpl is Simple {

    function chainId() private view returns (uint256 r) {
        assembly { r := chainid() }
    }

    bytes32 constant private DOMAIN_SEPARATOR_TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 immutable private DOMAIN_SEPARATOR = keccak256(abi.encode(
        DOMAIN_SEPARATOR_TYPE_HASH,
        keccak256(bytes("Simple")),
        keccak256(bytes("1")),
        chainId(),
        address(this)
    ));
    bytes32 constant private NONPAYABLE_BARE_TYPE_HASH = keccak256("NonpayableBare()");
    function nonpayableBare(
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        override
    {
        bytes memory buffer = abi.encodePacked(
            NONPAYABLE_BARE_TYPE_HASH
        );
        bytes32 message = keccak256(abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR,
            keccak256(buffer)
        ));
        address signer = ecrecover(message, v, r, s);
        require(address(0) != signer);
        return nonpayableBare(signer);
    }

    bytes32 constant private PAYABLE_TWO_RETURNS_TYPE_HASH = keccak256("PayableTwoReturns()");
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
        bytes memory buffer = abi.encodePacked(
            PAYABLE_TWO_RETURNS_TYPE_HASH
        );
        bytes32 message = keccak256(abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR,
            keccak256(buffer)
        ));
        address signer = ecrecover(message, v, r, s);
        require(address(0) != signer);
        return payableTwoReturns(signer);
    }

    bytes32 constant private VIEW_ONE_ARG_TYPE_HASH = keccak256("ViewOneArg(uint256 hello)");
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
        bytes memory buffer = abi.encodePacked(
            VIEW_ONE_ARG_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    abi.encode(hello)
                );
        }
        bytes32 message = keccak256(abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR,
            keccak256(buffer)
        ));
        address signer = ecrecover(message, v, r, s);
        require(address(0) != signer);
        return viewOneArg(signer, hello);
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
        .version("1")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"contract Level1Impl is Level1 {
    bytes32 constant private SOME_STRUCT_TYPE_HASH = keccak256("SomeStruct(uint256 a1,bytes b2)");
    function hashSomeStruct(SomeStruct calldata input712) private pure returns (bytes32) {
        bytes memory buffer = abi.encodePacked(
            SOME_STRUCT_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    abi.encode(input712.a1)
                );
        }
        {
                buffer = abi.encodePacked(
                    buffer,
                    keccak256(bytes(input712.b2))
                );
        }
        return keccak256(buffer);
    }


    function chainId() private view returns (uint256 r) {
        assembly { r := chainid() }
    }

    bytes32 constant private DOMAIN_SEPARATOR_TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 immutable private DOMAIN_SEPARATOR = keccak256(abi.encode(
        DOMAIN_SEPARATOR_TYPE_HASH,
        keccak256(bytes("Level1")),
        keccak256(bytes("1")),
        chainId(),
        address(this)
    ));
    bytes32 constant private DO_SOMETHING_TYPE_HASH = keccak256("DoSomething(SomeStruct foo)SomeStruct(uint256 a1,bytes b2)");
    function doSomething(
        SomeStruct calldata foo,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        override
    {
        bytes memory buffer = abi.encodePacked(
            DO_SOMETHING_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    hashSomeStruct(foo)
                );
        }
        bytes32 message = keccak256(abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR,
            keccak256(buffer)
        ));
        address signer = ecrecover(message, v, r, s);
        require(address(0) != signer);
        return doSomething(signer, foo);
    }

}
"#;

    assert_eq!(actual, expected);
}

#[test]
fn level2() {
    let abi = include_str!("abi/level2.json");
    let mut actual = String::new();

    Eip712::<()>::new("Level2")
        .version("1")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"contract Level2Impl is Level2 {
    bytes32 constant private INNER_STRUCT_TYPE_HASH = keccak256("InnerStruct(uint256 v)");
    function hashInnerStruct(InnerStruct calldata input712) private pure returns (bytes32) {
        bytes memory buffer = abi.encodePacked(
            INNER_STRUCT_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    abi.encode(input712.v)
                );
        }
        return keccak256(buffer);
    }

    bytes32 constant private OUTER_STRUCT_TYPE_HASH = keccak256("OuterStruct(InnerStruct inner)InnerStruct(uint256 v)");
    function hashOuterStruct(OuterStruct calldata input712) private pure returns (bytes32) {
        bytes memory buffer = abi.encodePacked(
            OUTER_STRUCT_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    hashInnerStruct(input712.inner)
                );
        }
        return keccak256(buffer);
    }


    function chainId() private view returns (uint256 r) {
        assembly { r := chainid() }
    }

    bytes32 constant private DOMAIN_SEPARATOR_TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 immutable private DOMAIN_SEPARATOR = keccak256(abi.encode(
        DOMAIN_SEPARATOR_TYPE_HASH,
        keccak256(bytes("Level2")),
        keccak256(bytes("1")),
        chainId(),
        address(this)
    ));
    bytes32 constant private DO_SOMETHING_TYPE_HASH = keccak256("DoSomething(OuterStruct input)InnerStruct(uint256 v)OuterStruct(InnerStruct inner)");
    function doSomething(
        OuterStruct calldata input,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        override
    {
        bytes memory buffer = abi.encodePacked(
            DO_SOMETHING_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    hashOuterStruct(input)
                );
        }
        bytes32 message = keccak256(abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR,
            keccak256(buffer)
        ));
        address signer = ecrecover(message, v, r, s);
        require(address(0) != signer);
        return doSomething(signer, input);
    }

}
"#;

    assert_eq!(actual, expected);
}

#[test]
fn array_in_struct() {
    let abi = include_str!("abi/arraystruct.json");
    let mut actual = String::new();

    Eip712::<()>::new("ArrayInStruct")
        .version("1")
        .read_str(abi)
        .unwrap()
        .generate(&mut actual)
        .unwrap();

    let expected = r#"contract ArrayInStructImpl is ArrayInStruct {
    bytes32 constant private SOME_STRUCT_TYPE_HASH = keccak256("SomeStruct(uint256[][] array)");
    function hashSomeStruct(SomeStruct calldata input712) private pure returns (bytes32) {
        bytes memory buffer = abi.encodePacked(
            SOME_STRUCT_TYPE_HASH
        );
        {
            bytes memory b0;
            for (uint a0 = 0; a0 < input712.array.length; ++a0) {
            bytes memory b1;
            for (uint a1 = 0; a1 < input712.array[a0].length; ++a1) {
                b1 = abi.encodePacked(
                    b1,
                    abi.encode(input712.array[a0][a1])
                );
            }
            b0 = abi.encodePacked(
                b0,
                keccak256(b1)
            );
            }
            buffer = abi.encodePacked(
                buffer,
                keccak256(b0)
            );
        }
        return keccak256(buffer);
    }


    function chainId() private view returns (uint256 r) {
        assembly { r := chainid() }
    }

    bytes32 constant private DOMAIN_SEPARATOR_TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 immutable private DOMAIN_SEPARATOR = keccak256(abi.encode(
        DOMAIN_SEPARATOR_TYPE_HASH,
        keccak256(bytes("ArrayInStruct")),
        keccak256(bytes("1")),
        chainId(),
        address(this)
    ));
    bytes32 constant private DO_SOMETHING_TYPE_HASH = keccak256("DoSomething(SomeStruct input)SomeStruct(uint256[][] array)");
    function doSomething(
        SomeStruct calldata input,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        public
        override
    {
        bytes memory buffer = abi.encodePacked(
            DO_SOMETHING_TYPE_HASH
        );
        {
                buffer = abi.encodePacked(
                    buffer,
                    hashSomeStruct(input)
                );
        }
        bytes32 message = keccak256(abi.encodePacked(
            hex"1901",
            DOMAIN_SEPARATOR,
            keccak256(buffer)
        ));
        address signer = ecrecover(message, v, r, s);
        require(address(0) != signer);
        return doSomething(signer, input);
    }

}
"#;

    assert_eq!(actual, expected);
}
