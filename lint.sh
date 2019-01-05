#!/usr/bin/env bash

set -e
set -v

# lint it using pyflakes
python3 -m pyflakes .

# typechecks
python3 -m mypy \
  --disallow-untyped-defs \
  --warn-unused-ignores \
  --ignore-missing-imports \
  --strict-optional \
  .

# check code style
pycodestyle --max-line-length=140 .

# enforce docstrings
pep257 --add-ignore=D202

# and now just to be really hard on yourself
pylint pckr scripts setup.py