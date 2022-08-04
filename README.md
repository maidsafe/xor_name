# xor_name

XorName is an array that is useful for calculations in DHT

| [MaidSafe website](http://maidsafe.net) | [SAFE Network Forum](https://safenetforum.org/) |
|:-------:|:-------:|

## Serialization

`XorName` and `Prefix` can be serialized into a human-readable hex string, instead of as a `u8` array. To enable this, activate the `serialize-hex` feature. This also allows for these structures to be serialised when used as a key in a map like `HashMap`, because most formats only allow keys to be strings, instead of more complex types.

A struct like this:
```rust
#[derive(Serialize, Deserialize)]
struct MyStruct {
    prefix: Prefix,
    xor_name: XorName,
}
```

Will yield this JSON
```json
{
  "prefix": "8a817b6d791f4b00000000000000000000000000000000000000000000000000/56",
  "xor_name": "8a817b6d791f4bae4117ac7ae15a88cd2c62fba0b040972ce885f1a47625dea1"
}
```

instead of
```json
{
    "prefix": {
        "bit_count": 56,
        "name": [141,199,202,57,183,222,153,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    },
    "xor_name": [141,199,202,57,183,222,153,14,185,67,253,100,133,71,118,221,133,170,130,195,58,66,105,105,60,87,179,110,7,73,237,143]
}
```

## License

This SAFE Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) https://opensource.org/licenses/MIT) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
