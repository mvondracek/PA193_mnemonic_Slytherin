#!/usr/bin/env python3
#
# BIP39 Mnemonic Phrase Generator and Verifier
#
# Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
# Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
# Masaryk University (MU)                         https://www.muni.cz/en
#
# Team Slytherin: @sobuch, @lsolodkova, @mvondracek.
#
# 2019
#
import sys
from unittest import TestCase

from pa193mnemonicslytherin.mnemonic import Entropy, Mnemonic, Seed, generate, recover, verify
from pa193mnemonicslytherin.test_mnemonic import get_random_valid_entropy_bytes, get_random_valid_mnemonic_phrase, \
    get_random_valid_password

try:
    # noinspection PyPackageRequirements
    from mnemonic import Mnemonic as TrezorMnemonic
except ImportError as e:
    print('{}\nPlease make sure `trezor/python-mnemonic` is installed. See `install.sh`.'.format(e), file=sys.stderr)
    sys.exit(1)


class TestMnemonicReference(TestCase):
    """
    Tests mnemonic module against reference implementation of `trezor/python-mnemonic`.

    https://github.com/trezor/python-mnemonic
    """
    SUBTEST_COUNT = 10

    def setUp(self) -> None:
        self.trezor = TrezorMnemonic("english")

    def test_generate(self):
        for i in range(self.SUBTEST_COUNT):
            password = get_random_valid_password()
            entropy_bytes = get_random_valid_entropy_bytes()
            with self.subTest(i=i, entropy_bytes=entropy_bytes, password=password):
                mnemonic_slytherin, seed__slytherin = generate(Entropy(entropy_bytes), password)
                mnemonic_trezor = self.trezor.to_mnemonic(entropy_bytes)
                seed_trezor = self.trezor.to_seed(mnemonic_trezor, password)
                self.assertEqual(mnemonic_trezor, mnemonic_slytherin)
                # `bytes(seed__slytherin)` cant use secure seed compare here hence the conversion to bytes
                self.assertEqual(seed_trezor, bytes(seed__slytherin))

    def test_recover(self):
        for i in range(self.SUBTEST_COUNT):
            password = get_random_valid_password()
            mnemonic_phrase = get_random_valid_mnemonic_phrase()
            with self.subTest(i=i, mnemonic_phrase=mnemonic_phrase, password=password):
                entropy_slytherin, seed_slytherin = recover(Mnemonic(mnemonic_phrase), password)
                entropy_trezor = self.trezor.to_entropy(mnemonic_phrase)
                seed_trezor = self.trezor.to_seed(mnemonic_phrase, password)
                self.assertEqual(entropy_trezor, entropy_slytherin)
                # `bytes(seed__slytherin)` cant use secure seed compare here hence the conversion to bytes
                self.assertEqual(seed_trezor, bytes(seed_slytherin))

    def test_verify(self):
        for i in range(self.SUBTEST_COUNT):
            password = get_random_valid_password()
            mnemonic_phrase = get_random_valid_mnemonic_phrase()
            seed_trezor = self.trezor.to_seed(mnemonic_phrase, password)
            with self.subTest(i=i, mnemonic_phrase=mnemonic_phrase, seed=seed_trezor, password=password):
                self.assertTrue(verify(Mnemonic(mnemonic_phrase), Seed(seed_trezor)))
