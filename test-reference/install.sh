#!/usr/bin/env bash
set -Eeuo pipefail
git clone https://github.com/trezor/python-mnemonic.git
cd python-mnemonic
pip install . --user # TODO it would be even better to use venv
