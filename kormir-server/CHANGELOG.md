# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.4](https://github.com/bennyhodl/kormir/compare/kormir-server-v0.3.3...kormir-server-v0.3.4) - 2025-01-17

### Added

- implement hmac authentication for create-* and sign-* endpoints

### Other

- return pubkey struct
- return the oracle info struct in kormir-server

## [0.3.1](https://github.com/bennyhodl/kormir/compare/kormir-server-v0.3.0...kormir-server-v0.3.1) - 2024-11-27

### Other

- use ddk versions of rust-dlc
- async ddk

## [0.3.0](https://github.com/bennyhodl/kormir/releases/tag/kormir-server-v0.3.0) - 2024-11-03

### Fixed

- fix saving nonce index in postgres

### Other

- release plz
- update rust-dlc to 0.7.0 ([#13](https://github.com/bennyhodl/kormir/pull/13))
- Add support for numeric events ([#6](https://github.com/bennyhodl/kormir/pull/6))
- Fix clippy
- Formatting
- Merge pull request [#9](https://github.com/bennyhodl/kormir/pull/9) from bennyhodl/get-by-event-id-routes
- bitcoin@0.32.2 & rust-dlc@0.6.0
- Upodate bitcoin 30.2 and rust-dlc 0.5
- Include the announcement/attestation ids and db id in server
- Bump version
- Update rust-nostr
- Bump version
- Update nostr, re-export it
- Bump version
- bump version
- Bump version
- Bump version
- Simplify code
- Bump versions
- Update deps
- Create and sign events for kormir-server
- Bump version
- List events
- Give outcome when saving signatures
- Remove unneeded clone
- Only allow one oracle per kormir-server
- Bump version
- Add crate metadata
- Add wasm support
- Remove anyhow
- Async storage
- Initial http server
- Project structure
