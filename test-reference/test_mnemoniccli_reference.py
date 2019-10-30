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
import os
import sys
from binascii import unhexlify, hexlify
from tempfile import TemporaryDirectory

from pa193mnemonicslytherin.mnemoniccli import Config, ExitCode
from pa193mnemonicslytherin.test_mnemonic import get_random_valid_entropy_bytes, get_random_valid_mnemonic_phrase, \
    get_random_valid_password
from pa193mnemonicslytherin.test_mnemoniccli import TestMainBase

try:
    # noinspection PyPackageRequirements
    from mnemonic import Mnemonic as TrezorMnemonic
except ImportError as e:
    print('{}\nPlease make sure `trezor/python-mnemonic` is installed. See `install.sh`.'.format(e), file=sys.stderr)
    sys.exit(1)


class TestMnemoniccliReference(TestMainBase):
    """
    Tests mnemoniccli tool against reference implementation of `trezor/python-mnemonic`.

    https://github.com/trezor/python-mnemonic
    """
    SUBTEST_COUNT = 10

    def setUp(self) -> None:
        self.trezor = TrezorMnemonic("english")

    def test_generate(self):
        # TODO refactor this method to use shared code with `TestMain.test_generate`
        for i in range(self.SUBTEST_COUNT):
            password = get_random_valid_password()
            entropy_bytes = get_random_valid_entropy_bytes()
            mnemonic_trezor = self.trezor.to_mnemonic(entropy_bytes)
            seed_trezor = self.trezor.to_seed(mnemonic_trezor, password)
            with self.subTest(i=i, entropy_bytes=entropy_bytes, password=password):
                with TemporaryDirectory() as tmpdir:
                    for io_format in Config.Format:  # type: Config.Format
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        entropy_path = os.path.join(tmpdir, '__entropy__')
                        with open(entropy_path, io_format.write_mode) as entropy_file:
                            entropy_file.write(
                                entropy_bytes if io_format is Config.Format.BINARY else str(hexlify(entropy_bytes),
                                                                                            'ascii'))
                        self.assert_program([self.SCRIPT, '-g', '--format', io_format.value, '-p', password,
                                             '-e', entropy_path,
                                             '-m', mnemonic_path,
                                             '-s', seed_path], ExitCode.EX_OK,
                                            stdout_check='[DONE] Generate, mnemonic in {}, seed in {}.\n'.format(
                                                mnemonic_path, seed_path),
                                            stderr_check='')
                        with open(seed_path, io_format.read_mode) as seed_file:
                            content = seed_file.read()
                            if io_format is Config.Format.BINARY:
                                seed = str(hexlify(content), 'ascii')
                            self.assertEqual(seed_trezor, unhexlify(seed))
                        with open(mnemonic_path, 'r') as mnemonic_file:
                            self.assertEqual(mnemonic_trezor, mnemonic_file.read())

    def test_recover(self):
        # TODO refactor this method to use shared code with `TestMain.test_recover`
        for i in range(self.SUBTEST_COUNT):
            password = get_random_valid_password()
            mnemonic_phrase = get_random_valid_mnemonic_phrase()
            entropy_trezor = self.trezor.to_entropy(mnemonic_phrase)
            seed_trezor = self.trezor.to_seed(mnemonic_phrase, password)
            with self.subTest(i=i, mnemonic_phrase=mnemonic_phrase, password=password):
                with TemporaryDirectory() as tmpdir:
                    for io_format in Config.Format:  # type: Config.Format
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        entropy_path = os.path.join(tmpdir, '__entropy__')
                        with open(mnemonic_path, 'w') as mnemonic_file:
                            mnemonic_file.write(mnemonic_phrase)
                        self.assert_program([self.SCRIPT, '-r', '--format', io_format.value, '-p', password,
                                             '-e', entropy_path,
                                             '-m', mnemonic_path,
                                             '-s', seed_path], ExitCode.EX_OK,
                                            stdout_check='[DONE] Recover, entropy in {}, seed in {}.\n'.format(
                                                entropy_path, seed_path),
                                            stderr_check='')
                        with open(seed_path, io_format.read_mode) as seed_file:
                            content = seed_file.read()
                            if io_format is Config.Format.BINARY:
                                seed = str(hexlify(content), 'ascii')
                            self.assertEqual(seed_trezor, unhexlify(seed))
                        with open(entropy_path, io_format.read_mode) as entropy_file:
                            content = entropy_file.read()
                            if io_format is Config.Format.BINARY:
                                entropy = str(hexlify(content), 'ascii')
                            self.assertEqual(entropy_trezor, unhexlify(entropy))

    def test_verify(self):
        # TODO refactor this method to use shared code with `TestMain.test_verify`
        for i in range(self.SUBTEST_COUNT):
            password = get_random_valid_password()
            mnemonic_phrase = get_random_valid_mnemonic_phrase()
            seed_trezor = self.trezor.to_seed(mnemonic_phrase, password)
            with self.subTest(i=i, mnemonic_phrase=mnemonic_phrase, seed=seed_trezor, password=password):
                with TemporaryDirectory() as tmpdir:
                    for io_format in Config.Format:  # type: Config.Format
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        with open(mnemonic_path, 'w') as mnemonic_file:
                            mnemonic_file.write(mnemonic_phrase)
                        with open(seed_path, io_format.write_mode) as seed_file:
                            seed_file.write(
                                seed_trezor if io_format is Config.Format.BINARY else str(hexlify(seed_trezor),
                                                                                          'ascii'))
                        self.assert_program([self.SCRIPT, '-v', '--format', io_format.value, '-p', password,
                                             '-m', mnemonic_path,
                                             '-s', seed_path], ExitCode.EX_OK,
                                            stdout_check='Seeds match.\n',
                                            stderr_check='')
