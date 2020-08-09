# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

1. Platform specific problem with invalid Gzip files when using -Z.
1. Add additional metadata to Gzip files when using -Z.

## [1.3.0] - 2020-08-08

### Added

1. Added Visual Studio Code Development Container configuration.
1. Data written to outfile may now be compressed.

### Fixed

1. Corrected the URL included in the usage message.

## [1.2.2] - 2020-08-07

### Changed

1. [README]: Added explanation for field `mailID` in JSON results.
1. Improved validity check for e-mail addresses found in logfiles.

## [1.2.1] - 2020-07-20

### Fixed

1. Correct exit codes for errors.
1. Actually update the version string displayed with --version.
1. Include new information in [README].

## [1.2.0] - 2020-07-20

### Added

1. This changelog.
1. Contribution guide, see [CONTRIBUTING.md](CONTRIBUTING.md).
1. Option --no-csv-header to omit the header line in CSV output.
1. Option --outfile to redirect output into a file.

## [1.1.0] - 2020-07-19

### Added

1. Indication of performance, see [PERFORMANCE.md](PERFORMANCE.md).
1. Support for reading gzip'ed logfiles directly.

## [1.0.0] - 2020-07-18

Initial public release.

### Added

1. Parsing of uncompressed logfiles.
1. Support for CSV output (default).
1. Support for JSON output.
1. Support for defining internal hosts.

[Unreleased]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/compare/v1.3.0...master
[1.3.0]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/compare/v1.2.2...v1.3.0
[1.2.2]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/compare/v1.2.1...v1.2.2
[1.2.1]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/compare/v1.2.0...v1.2.1
[1.2.0]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/compare/v1.0.0...v1.1.0
[1.0.0]: https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser/-/tree/v1.0.0
[README]: README.md
