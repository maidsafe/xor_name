# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [1.1.1](https://github.com/maidsafe/xor_name/compare/v1.1.0...v1.1.1) (2020-09-21)

### [1.1.0](https://github.com/maidsafe/xor_name/compare/v1.0.0...v1.1.0) (2020-08-18)
* Add in `XorName::random()` functionality
* Use OSRng

### [1.0.0](https://github.com/maidsafe/xor_name/compare/0.9.2...v1.0.0) (2020-07-02)
* Make the crate no_std
* Add impl Deref for XorName, remove slice indexing
* Minimise the API surface
* Remove generics

### [0.9.2]
* Remove test barrier from the FromStr trait impl for Prefix

### [0.9.1]
* Added borrow trait for prefix

### [0.9.0]
* Extracted from the routing crate to become standalone (again)
* License details updated to MIT or modified BSD license.
* CI set up on GitHub Actions

### [0.1.0]
* Replace CBOR usage with maidsafe_utilites::serialisation.
* Updated dependencies.

### [0.0.5]
* Migrate to maidsafe_utilities 0.2.1.
* Make debug hex output lowercase.

### [0.0.4]
* Reduce debug output to improve readability.

### [0.0.3]
* Add the `with_flipped_bit` and `count_differing_bits` methods.
* Rename `cmp_closeness` to `cmp_distance`.

### [0.0.2]
* Rename `bucket_distance` to `bucket_index`.
* Expand documentation.
* Add `XorName::cmp_closeness` ordering method.

### [0.0.1]
* Initial implementation
