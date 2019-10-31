#!/usr/bin/env bash
##
## Generates documentation in `./docs/html/index.html`.
## Use Sphinx 2.2.1 or compatible.
##
## BIP39 Mnemonic Phrase Generator and Verifier
##
## Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
## Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
## Masaryk University (MU)                         https://www.muni.cz/en
##
## Team Slytherin: @sobuch, @lsolodkova, @mvondracek.
##
## 2019

set -Eeuo pipefail

command -v sphinx-build >/dev/null 2>&1 || {
  echo >&2 "Please install Sphinx==2.2.1 (sphinx-build)"
  exit 1
}
command -v sphinx-apidoc >/dev/null 2>&1 || {
  echo >&2 "Please install Sphinx==2.2.1 (sphinx-apidoc)"
  exit 1
}

project="pa193mnemonicslytherin - BIP39 Mnemonic Phrase Generator and Verifier"
author="Team Slytherin: @sobuch, @lsolodkova, @mvondracek."
version="1.0"
release="1.0.0"

sphinx-apidoc --force --module-first --no-toc \
-H "${project}" -A "${author}" -V "${version}" -R "${release}" \
-o ./docs ./pa193mnemonicslytherin \
"pa193mnemonicslytherin/test_*" "pa193mnemonicslytherin/mnemoniccli.py"
cd ./docs
cat <<'EOF' >index.rst
BIP39 Mnemonic Phrase Generator and Verifier
============================================

.. toctree::
   :maxdepth: 4
   :caption: Contents:

   pa193mnemonicslytherin
EOF
sphinx-build -b singlehtml -C \
-D html_theme=classic \
-D add_module_names=0 \
-D extensions=sphinx.ext.autodoc \
-D project="${project}" \
-D copyright="2019, ${author}" \
-D author="${author}" \
-D version="${version}" \
-D release="${release}" \
. html
