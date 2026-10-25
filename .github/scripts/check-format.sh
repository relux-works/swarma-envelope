#!/usr/bin/env bash
# Invoke with bash -eo pipefail; a standalone capture preserves formatter errors.
format_output="$(gofmt -l "${1:-.}")"
test -z "$format_output"
