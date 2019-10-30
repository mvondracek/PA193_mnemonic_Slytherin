#!/usr/bin/env bash
set -Eeuo pipefail
git clone https://github.com/trezor/python-mnemonic.git
cd python-mnemonic
sudo python setup.py install

