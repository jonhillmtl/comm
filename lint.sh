#!/usr/bin/env bash

set -e
set -v

# lint it using pyflakes
python3 -m pyflakes .

# typechecks
# python3 -m mypy --warn-unused-ignores --ignore-missing-imports --strict-optional --disallow-untyped-defs .

# and now just to be really hard on yourself
# pylint pckr scripts setup.py --max-line-length=140 -d C0111 -d W0511 -d R0904 -d R0912 -d R0914 -d R0913

# enforce docstrings
pep257 --add-ignore=D202,D210

# check code style
pycodestyle --max-line-length=140 .
