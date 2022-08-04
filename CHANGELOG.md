# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [4.1.0](https://github.com/maidsafe/xor_name/compare/v4.0.1...v4.1.0) (2022-08-04)


### Features

* serialize to string ([9d54992](https://github.com/maidsafe/xor_name/commit/9d54992cdf519d66524fd9fdbedb53780133c183))

### [4.0.1](https://github.com/maidsafe/xor_name/compare/v4.0.0...v4.0.1) (2022-03-18)

## [4.0.0](https://github.com/maidsafe/xor_name/compare/v3.1.0...v4.0.0) (2022-03-16)


### ⚠ BREAKING CHANGES

* public api changed

* remove OsRng ([c4d64e9](https://github.com/maidsafe/xor_name/commit/c4d64e98556e5c9caff902182c9e840dad869580))

## [3.1.0](https://github.com/maidsafe/xor_name/compare/v3.0.0...v3.1.0) (2021-08-26)


### Features

* **api:** simplify from content api ([441acc7](https://github.com/maidsafe/xor_name/commit/441acc7269747cff6868adf425cd0be6c12b39e5))

## [3.0.0](https://github.com/maidsafe/xor_name/compare/v2.0.0...v3.0.0) (2021-08-24)


### ⚠ BREAKING CHANGES

* remove prefix_map

### Features

* remove prefix_map make with_bit public ([efa63e2](https://github.com/maidsafe/xor_name/commit/efa63e26dc3820c6ba1cdeaf270f41030684fa09))
* use DashMaps for better concurrency ([2ef45f3](https://github.com/maidsafe/xor_name/commit/2ef45f328699ccb8a750b8f0e5788b792414f3c1))

## [2.0.0](https://github.com/maidsafe/xor_name/compare/v1.3.0...v2.0.0) (2021-08-10)


### ⚠ BREAKING CHANGES

* **prefix-map:**  - Expose PrefixMap as public from lib and remove pub prefix_map mod.
 - Adapting PrefixMap APIs to the removal of requirement of Borrow<Prefix> Trait for T.

* **prefix-map:** remove the requirement of Borrow<Prefix> trait for T from PrefixMap ([1e32830](https://github.com/maidsafe/xor_name/commit/1e32830af72ae37f58a9961b8a0c8dde0981b0e0))

## [1.3.0](https://github.com/maidsafe/xor_name/compare/v1.2.1...v1.3.0) (2021-08-06)


### Features

* insert returns bool ([7e36f9d](https://github.com/maidsafe/xor_name/commit/7e36f9dfeb49765b281625f07ec64fd320c666d2))
* prefix map ([83be995](https://github.com/maidsafe/xor_name/commit/83be99545a3dda1fdb9d0c13a9d18a757bec8538))
* remove get_equal_or_ancestor ([4c2c7ed](https://github.com/maidsafe/xor_name/commit/4c2c7ed40db22f14a8548d8bb6e36589a0111165))
* use BTreeMap add get_matching_prefix make prune pub ([069767c](https://github.com/maidsafe/xor_name/commit/069767ce0e98a86e9b04f8efa2c91225968e022d))

### [1.2.1](https://github.com/maidsafe/xor_name/compare/v1.2.0...v1.2.1) (2021-06-08)

## [1.2.0](https://github.com/maidsafe/xor_name/compare/v1.1.12...v1.2.0) (2021-04-19)


### Features

* Debug output with binary fmt as well ([1382403](https://github.com/maidsafe/xor_name/commit/1382403befe73de1961fcde8ec6cfa042dd36fb0))

### [1.1.12](https://github.com/maidsafe/xor_name/compare/v1.1.11...v1.1.12) (2021-03-03)

### [1.1.11](https://github.com/maidsafe/xor_name/compare/v1.1.10...v1.1.11) (2021-02-25)

### [1.1.10](https://github.com/maidsafe/xor_name/compare/v1.1.9...v1.1.10) (2021-02-09)

### [1.1.9](https://github.com/maidsafe/xor_name/compare/v1.1.8...v1.1.9) (2021-02-03)

### [1.1.8](https://github.com/maidsafe/xor_name/compare/v1.1.7...v1.1.8) (2021-02-03)

### [1.1.7](https://github.com/maidsafe/xor_name/compare/v1.1.6...v1.1.7) (2021-01-20)

### [1.1.6](https://github.com/maidsafe/xor_name/compare/v1.1.5...v1.1.6) (2021-01-14)

### [1.1.5](https://github.com/maidsafe/xor_name/compare/v1.1.4...v1.1.5) (2021-01-06)

### [1.1.4](https://github.com/maidsafe/xor_name/compare/v1.1.3...v1.1.4) (2020-11-23)

### [1.1.3](https://github.com/maidsafe/xor_name/compare/v1.1.2...v1.1.3) (2020-10-09)

### [1.1.2](https://github.com/maidsafe/xor_name/compare/v1.1.1...v1.1.2) (2020-10-09)

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
