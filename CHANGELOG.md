# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Changed
- Changed name of `Error::AuthError` to `Error::Auth`

### Added
- Added new field to `Error::InvalidRsaKey`
- Added new Error varient `Error::InvalidRsaKeyRejected` 
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
[Unreleased]: https://github.com/EmbarkStudios/tame-oauth/compare/0.4.7...HEAD
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
