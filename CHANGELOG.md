<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
## [0.9.6] - 2023-11-20
### Changed
- [PR#67](https://github.com/EmbarkStudios/tame-oauth/pull/67) upgraded `ring` from 0.16 -> 0.17.

## [0.9.4] - 2023-10-04
### Changed
- [PR#66](https://github.com/EmbarkStudios/tame-oauth/pull/66) replaced `base64` with `data-encoding`.

## [0.9.3] - 2023-06-09
### Fixed
- [PR#65](https://github.com/EmbarkStudios/tame-oauth/pull/65) Use url safe base64 when decoding jwt claims from id tokens.

## [0.9.2] - 2023-04-25
### Fixed
- [PR#63](https://github.com/EmbarkStudios/tame-oauth/pull/63) Use correct base64 padding when decoding jwt claims from id tokens.

## [0.9.1] - 2023-03-29
### Added
- Support for id tokens, a new trait for this was added (`IdTokenProvider`) and implemented for all current token providers so both access tokens and id tokens can be fetched.
- Added `is_*_provider` methods to `TokenProviderWrapper` for asserting the inner type.
- [PR#61](https://github.com/EmbarkStudios/tame-oauth/pull/61) added debug implementations for all the providers (excludes sensitive data in the output).

### Changed
- `RequestReason::ScopesChanged` was renamed to `RequestReason::ParametersChanged`
- [PR#59](https://github.com/EmbarkStudios/tame-oauth/pull/59) update outdated base64 dependency
- Moved the placement of the `CachedTokenProvider` on `TokenProviderWrapper` so that it wraps the outer type instead of the inner, that way the uncached provider can be accessed via `.inner()`.

### Fixed
- [PR#57](https://github.com/EmbarkStudios/tame-oauth/pull/57) Documentation improvements

## 0.9.0 - 2023-03-29
Release failed and was yanked. Released as 0.9.1 instead.

## [0.8.1] - 2023-01-10
### Fixed
- [PR#54](https://github.com/EmbarkStudios/tame-oauth/pull/54) re-adds `get_account_info` to the outer `ServiceAccountProvider` implementation. It was accidentally removed in #51.

## [0.8.0] - 2023-01-10
### Changed
- [PR#51](https://github.com/EmbarkStudios/tame-oauth/pull/51) moved the token cache out of `ServiceAccountProvider` into a public type, and added a cached token provider that can wrap any other token provider. This wrapper now wraps all the current gcp token providers, making them cached by default.
- [PR#53](https://github.com/EmbarkStudios/tame-oauth/pull/53) changed the cache lock from a Mutex into a RwLock.

## [0.7.0] - 2022-02-02
### Changed
- [PR#47](https://github.com/EmbarkStudios/tame-oauth/pull/47) removed the dependency upon `chrono` as it was overkill and brought in multiple security advisories and is only lightly maintained.

## [0.6.0] - 2021-08-07
### Added
- [PR#40](https://github.com/EmbarkStudios/tame-oauth/pull/40) added support for [`Metadata Server Auth`](https://cloud.google.com/compute/docs/instances/verifying-instance-identity) so that you can obtain oauth tokens when running inside GCP. Thanks [@boulos](https://github.com/boulos)!
- [PR#42](https://github.com/EmbarkStudios/tame-oauth/pull/42) resolved [#39](https://github.com/EmbarkStudios/tame-oauth/issues/39) by adding support for the same default credentials flow as the the Go [oauth2](https://github.com/golang/oauth2/blob/f6687ab2804cbebdfdeef385bee94918b1ce83de/google/default.go#L111) implementation for Google oauth. This included adding support for `EndUserCredentials`. Thanks [@boulos](https://github.com/boulos)!

## [0.5.2] - 2021-06-18
### Added
- [PR#38](https://github.com/EmbarkStudios/tame-oauth/pull/38) added `ServiceAccountAccess::get_token_with_subject` to allow control over the JWT `subject` field. Thanks [@fosskers](https://github.com/fosskers)!

## [0.5.1] - 2021-06-05
### Removed
- Removed unused dependency on `lock_api`, which was lingering after [PR#21](https://github.com/EmbarkStudios/tame-oauth/pull/21).

## [0.5.0] - 2021-06-05
### Added
- Added new field to `Error::InvalidRsaKey`
- Added `Error::InvalidRsaKeyRejected` variant
- [PR#37](https://github.com/EmbarkStudios/tame-oauth/pull/37) Added new feature `wasm-web`, which enables additional features in `chrono` and `ring` to allow `tame-oauth` to be used in a wasm browser context, as part of a fix for [#36](https://github.com/EmbarkStudios/tame-oauth/issues/36).

### Changed
- Changed name of `Error::AuthError` to `Error::Auth`
- [PR#37](https://github.com/EmbarkStudios/tame-oauth/pull/37) replaced the usage of `parking_lot::Mutex` with just regular `std::sync::Mutex` as part of the fix for [#36](https://github.com/EmbarkStudios/tame-oauth/issues/36), this includes adding `Error::Poisoned`.

### Removed
- Removed `Error:Io` as it was never actually used.

## [0.4.7] - 2021-01-18
### Changed
- Updated `base64` to `0.13`, matching the version used by rustls

## [0.4.6] - 2021-01-09
### Changed
- Updated url to 2.2

## [0.4.5] - 2020-10-30
### Added
- Added `ServiceAccountAccess::get_account_info`.

## [0.4.4] - 2020-10-10
### Fixed
- [#21](https://github.com/EmbarkStudios/tame-oauth/pull/21) Fixed a rather serious bug [#20](https://github.com/EmbarkStudios/tame-oauth/issues/20) due to a terribly implemented spinlock. Thanks for the report [@fasterthanlime](https://github.com/fasterthanlime)!

## [0.4.3] - 2020-06-04
### Changed
- Updated dependencies

## [0.4.2] - 2020-01-21
### Changed
- Updated dependencies
- Made `svc_account` example async

## [0.4.1] - 2019-12-20
### Removed
- Removed `bytes` dependency which was only used by the svc_account example

## [0.4.0] - 2019-12-20
### Changed
- Upgraded `http` to `0.2.0`

## [0.3.1] - 2019-12-05
### Changed
- Updated several dependencies

## [0.3.0] - 2019-10-10
### Changed
- Upgraded `ring` to `0.16.9`

### Removed
- Removed use of failure

## [0.2.1] - 2019-07-15
### Changed
- Updated `parking_lot`.

## [0.2.0] - 2019-07-03
### Added
- Fleshed out documentation.
- Added prelude for `gcp`

### Fixed
- Correctly used rustls in tests/examples.

## [0.1.0] - 2019-07-02
### Added
- Initial add of `tame-oauth`

<!-- next-url -->
[Unreleased]: https://github.com/EmbarkStudios/tame-oauth/compare/0.9.6...HEAD
[0.9.6]: https://github.com/EmbarkStudios/tame-oauth/compare/0.9.4...0.9.6
[0.9.4]: https://github.com/EmbarkStudios/tame-oauth/compare/0.9.3...0.9.4
[0.9.3]: https://github.com/EmbarkStudios/tame-oauth/compare/0.9.2...0.9.3
[0.9.2]: https://github.com/EmbarkStudios/tame-oauth/compare/0.9.1...0.9.2
[0.9.1]: https://github.com/EmbarkStudios/tame-oauth/compare/0.8.1...0.9.1
[0.8.1]: https://github.com/EmbarkStudios/tame-oauth/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.5.2...0.6.0
[0.5.2]: https://github.com/EmbarkStudios/tame-oauth/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/EmbarkStudios/tame-oauth/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.7...0.5.0
[0.4.7]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.6...0.4.7
[0.4.6]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.5...0.4.6
[0.4.5]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.4...0.4.5
[0.4.4]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.3...0.4.4
[0.4.3]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/EmbarkStudios/tame-oauth/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/EmbarkStudios/tame-oauth/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/EmbarkStudios/tame-oauth/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/EmbarkStudios/tame-oauth/releases/tag/0.1.0
