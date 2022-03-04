// Copyright (c) 2022 Sam Wilson.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::abi::{Kind, Parameter};

pub fn encode_type(param: &Parameter) -> String {
    let mut top_type = Vec::new();
    let mut extra_types = BTreeMap::new();
    let mut extra_types_todo = Vec::new();

    for input in param.components() {
        let short_kind;

        if input.kind().base_kind() == Kind::tuple() {
            extra_types_todo.push((input.internal_kind().base_kind(), input.components()));

            short_kind = input.internal_kind().shorten_kind();
        } else {
            short_kind = input.kind().to_string();
        }

        top_type.push((short_kind, input.name()));
    }

    while let Some((internal_kind, components)) = extra_types_todo.pop() {
        let short_kind = internal_kind.base_kind().shorten_kind();

        if extra_types.contains_key(&short_kind) {
            continue;
        }

        let mut args = Vec::with_capacity(components.len());

        for component in components {
            let arg_kind;
            if component.kind().base_kind() == Kind::tuple() {
                extra_types_todo.push((
                    component.internal_kind().base_kind(),
                    component.components(),
                ));
                arg_kind = component.internal_kind().shorten_kind();
            } else {
                arg_kind = component.kind().to_string();
            }

            let params = format!("{} {}", arg_kind, component.name());
            args.push(params);
        }

        extra_types.insert(short_kind, args.join(","));
    }

    let sig = top_type
        .iter()
        .map(|(k, n)| format!("{} {}", k, n))
        .collect::<Vec<_>>()
        .join(",");

    let mut result = format!("{}({})", param.internal_kind().shorten_kind(), sig);

    for (name, args) in extra_types.iter() {
        result.push_str(name);
        result.push('(');
        result.push_str(args);
        result.push(')');
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::abi::Function;

    use super::*;

    #[crate::test]
    fn encode_type_bare() {
        let input = r#"{
            "inputs": [
                {
                    "internalType": "uint8",
                    "name": "v",
                    "type": "uint8"
                },
                {
                    "internalType": "bytes32",
                    "name": "r",
                    "type": "bytes32"
                },
                {
                    "internalType": "bytes32",
                    "name": "s",
                    "type": "bytes32"
                }
            ],
            "name": "nonpayableBare",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }"#;

        let func: Function = serde_json::from_str(&input).unwrap();
        let param = func.into_input_parameter();
        let actual = encode_type(&param);

        assert_eq!("NonpayableBare()", actual);
    }

    #[crate::test]
    fn encode_type_one_arg() {
        let input = r#"{
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "hello",
                    "type": "uint256"
                },
                {
                    "internalType": "uint8",
                    "name": "v",
                    "type": "uint8"
                },
                {
                    "internalType": "bytes32",
                    "name": "r",
                    "type": "bytes32"
                },
                {
                    "internalType": "bytes32",
                    "name": "s",
                    "type": "bytes32"
                }
            ],
            "name": "viewOneArg",
            "outputs": [],
            "stateMutability": "view",
            "type": "function"
        }"#;

        let func: Function = serde_json::from_str(&input).unwrap();
        let param = func.into_input_parameter();
        let actual = encode_type(&param);

        assert_eq!("ViewOneArg(uint256 hello)", actual);
    }

    #[crate::test]
    fn encode_type_complex() {
        let input = r#"{
            "inputs": [
                {
                    "components": [
                        {
                            "internalType": "bytes",
                            "name": "bye",
                            "type": "bytes"
                        },
                        {
                            "components": [
                                {
                                    "internalType": "uint256",
                                    "name": "hi",
                                    "type": "uint256"
                                }
                            ],
                            "internalType": "struct Foo.Msg1",
                            "name": "hi",
                            "type": "tuple"
                        },
                        {
                            "components": [
                                {
                                    "internalType": "uint256",
                                    "name": "hi",
                                    "type": "uint256"
                                }
                            ],
                            "internalType": "struct Foo.Msg1[][]",
                            "name": "high",
                            "type": "tuple[][]"
                        },
                        {
                            "internalType": "bytes32",
                            "name": "h",
                            "type": "bytes32"
                        }
                    ],
                    "internalType": "struct Foo.Msg2",
                    "name": "foo",
                    "type": "tuple"
                },
                {
                    "internalType": "uint8",
                    "name": "v",
                    "type": "uint8"
                },
                {
                    "internalType": "bytes32",
                    "name": "r",
                    "type": "bytes32"
                },
                {
                    "internalType": "bytes32",
                    "name": "s",
                    "type": "bytes32"
                }
            ],
            "name": "recover",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }"#;

        let func: Function = serde_json::from_str(&input).unwrap();
        let param = func.into_input_parameter();
        let actual = encode_type(&param);

        assert_eq!(
            "Recover(Msg2 foo)Msg1(uint256 hi)Msg2(bytes bye,Msg1 hi,Msg1[][] high,bytes32 h)",
            actual
        );
    }
}
