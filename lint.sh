#!/usr/bin/env bash

set -e
set -v

# python3 -m pyflakes .

# typechecks
python3 -m mypy \
  --warn-unused-ignores \
  --ignore-missing-imports \
  --strict-optional \
  .

pycodestyle --max-line-length=140 .