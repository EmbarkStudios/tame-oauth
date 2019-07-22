#!/bin/bash
set -e

travis_fold start "rustup.component.install"
    travis_time_start
        rustup component add rustfmt clippy
    travis_time_finish
travis_fold end "rustup.component.install"

# Ensure everything has been rustfmt'ed
travis_fold start "rustfmt"
    travis_time_start
        cargo fmt -- --check
    travis_time_finish
travis_fold end "rustfmt"

# Download in a separate step to separate
# building from fetching dependencies
travis_fold start "cargo.fetch"
    travis_time_start
        cargo fetch
    travis_time_finish
travis_fold end "cargo.fetch"

# Because rust isn't brutal enough itself
travis_fold start "clippy"
    travis_time_start
        cargo clippy -- -D warnings
    travis_time_finish
travis_fold end "clippy"

# Ensure we aren't accidentally using dependencies
# we don't want
deny_version=0.2.5
name="cargo-deny-$deny_version-x86_64-unknown-linux-musl"
travis_fold start "cargo-deny"
    travis_time_start
        curl -L --output archive.tar.gz https://github.com/EmbarkStudios/cargo-deny/releases/download/$deny_version/$name.tar.gz
        tar -zxvf archive.tar.gz $name/cargo-deny
        rm archive.tar.gz

        $name/cargo-deny check
    travis_time_finish
travis_fold end "cargo-deny"
