#!/bin/bash
set -e

# Fetch dependencies in a different step to clearly
# delineate between downloading and building
travis_fold start "cargo.fetch"
    travis_time_start
        cargo fetch
    travis_time_finish
travis_fold end "cargo.fetch"

# Build without running to clearly delineate between
# building and running the tests
travis_fold start "cargo.build"
    travis_time_start
        cargo test --no-run
    travis_time_finish
travis_fold end "cargo.build"

travis_fold start "cargo.test"
    travis_time_start
        cargo test
    travis_time_finish
travis_fold end "cargo.test"
