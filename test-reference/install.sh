#!/usr/bin/env bash
set -Eeuo pipefail
git clone https://github.com/trezor/python-mnemonic.git
cd python-mnemonic
pip install . # it is better to use venv
