"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import os
import subprocess
import unittest
from binascii import hexlify, unhexlify
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from tempfile import TemporaryDirectory
from typing import Optional, List, Tuple, Union

from pa193mnemonicslytherin.mnemonic import MAX_SEED_PASSWORD_LENGTH, SEED_LEN
from pa193mnemonicslytherin.mnemoniccli import ExitCode, cli_entry_point, Config
from pa193mnemonicslytherin.test_mnemonic import TREZOR_TEST_VECTORS, TREZOR_PASSWORD, \
    VALID_SEED_HEX_TREZOR, VALID_MNEMONIC_PHRASE_TREZOR


def get_invalid_entropies() -> List[Tuple[Union[str, bytes], Config.Format, Optional[str]]]:
    """
    > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is improved but
    > the sentence length increases. We refer to the initial entropy length as ENT. The allowed size of ENT
    > is 128-256 bits.
    > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic

    :return: List of invalid examples as tuples, where first is invalid input,
             second is format of this input, and third is optional error
             message to be checked on program's stderr.
    """
    invalid_entropies = []
    # region invalid length
    entropy_byte = b'\x01'
    valid_entropy_bytes_lengths = (16, 20, 24, 28, 32)
    for entropy_bytes_length in range(0, 40):
        if entropy_bytes_length not in valid_entropy_bytes_lengths:
            invalid_entropies.append((entropy_byte * entropy_bytes_length, Config.Format.BINARY, None))
            invalid_entropies.append((str(hexlify(entropy_byte * entropy_bytes_length), 'ascii'),
                                      Config.Format.TEXT_HEXADECIMAL, None))
    # endregion
    # TODO invalid characters in hex string
    return invalid_entropies


def get_invalid_mnemonics() -> List[Tuple[str, Optional[str]]]:
    """
    :return: List of invalid examples as tuples, where first is invalid input,
             and second is optional error message to be checked on
             program's stderr.
    """
    invalid_mnemonics = [('this is invalid mnemonic', None)]  # TODO gather invalid mnemonics from tests
    # TODO invalid UTF-8 sequences
    return invalid_mnemonics


def get_invalid_seeds() -> List[Tuple[Union[str, bytes], Config.Format, Optional[str]]]:
    """
    :return: List of invalid examples as tuples, where first is invalid input,
             second is format of this input, and third is optional error
             message to be checked on program's stderr.
    """
    invalid_seeds = []
    # region invalid length
    seed_byte = b'\xff'
    for seed_bytes_length in range(0, SEED_LEN + 3):
        if seed_bytes_length != SEED_LEN:
            invalid_seeds.append((seed_byte * seed_bytes_length, Config.Format.BINARY, None))
            invalid_seeds.append((str(hexlify(seed_byte * seed_bytes_length), 'ascii'),
                                  Config.Format.TEXT_HEXADECIMAL, None))
    # endregion
    # TODO invalid characters in hex string
    return invalid_seeds


class TestMainBase(unittest.TestCase):
    """Integration tests for CLI tool."""
    TIMEOUT = 5  # seconds until we terminate the program
    PYTHON = 'python'
    SCRIPT = 'mnemoniccli.py'
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

    def execute_cli(self, args: List[str]):
        return subprocess.run([self.PYTHON] + args, timeout=self.TIMEOUT, cwd=self.SCRIPT_DIR,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    def assert_program_cli(self, args: List[str], exitcode: ExitCode,
                           stdout_check: Optional[str] = None, stderr_check: Optional[str] = None):
        """Run CLI program and assert its result.
        :param args: arguments for the program
        :param exitcode: expected exit code
        :param stdout_check: String with which `stdout` should be compared, `None` if `stdout` should not be empty.
        :param stderr_check: String with which `stderr` should be compared, `None` if `stderr` should not be empty.
        """
        cli = self.execute_cli(args)
        self.assertEqual(exitcode.value, cli.returncode)
        if stdout_check is not None:
            self.assertEqual(stdout_check, cli.stdout)
        else:
            self.assertNotEqual('', cli.stdout)
        if stderr_check is not None:
            self.assertEqual(stderr_check, cli.stderr)
        else:
            self.assertNotEqual('', cli.stderr)

    def assert_program_entry_point(self, args: List[str], exitcode: ExitCode,
                                   stdout_check: Optional[str] = None, stderr_check: Optional[str] = None):
        """Run program directly from the test for counted test coverage and assert its result.
        :param args: arguments for the program
        :param exitcode: expected exit code
        :param stdout_check: String with which `stdout` should be compared, `None` if `stdout` should not be empty.
        :param stderr_check: String with which `stderr` should be compared, `None` if `stderr` should not be empty.
        """
        stdout_redirected = StringIO()
        stderr_redirected = StringIO()
        with redirect_stdout(stdout_redirected), redirect_stderr(stderr_redirected):
            with self.assertRaises(SystemExit) as cm:
                cli_entry_point(args)  # remove `python` from args
        if stdout_check is not None:
            self.assertEqual(stdout_check, stdout_redirected.getvalue())
        else:
            self.assertNotEqual('', stdout_redirected.getvalue())
        if stderr_check is not None:
            self.assertEqual(stderr_check, stderr_redirected.getvalue())
        else:
            self.assertNotEqual('', stderr_redirected.getvalue())
        self.assertEqual(exitcode.value, cm.exception.args[0])

    def assert_program(self, args: List[str], exitcode: ExitCode,
                       stdout_check: Optional[str] = None, stderr_check: Optional[str] = None):
        """Run program and assert its result.
        Runs program twice, first time using subprocess for more realistic behaviour from command line and then directly
        from the test for counted test coverage.
        :param args: arguments for the program
        :param exitcode: expected exit code
        :param stdout_check: String with which `stdout` should be compared, `None` if `stdout` should not be empty.
        :param stderr_check: String with which `stderr` should be compared, `None` if `stderr` should not be empty.
        """
        self.assert_program_cli(args, exitcode, stdout_check, stderr_check)
        # Execute program inside this test now, because test coverage is not counted when we execute CLI as subprocess.
        self.assert_program_entry_point(args, exitcode, stdout_check, stderr_check)

    def assert_program_error(self, args: List[str], exitcode: ExitCode):
        self.assert_program(args, exitcode, stdout_check='', stderr_check=None)

    def assert_program_success(self, args: List[str]):
        self.assert_program(args, ExitCode.EX_OK, stdout_check=None, stderr_check='')


class TestMain(TestMainBase):
    def test_arguments_error(self):
        """invalid arguments"""
        self.assert_program_error([self.SCRIPT], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-ll', 'FOO'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-g'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-r'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-v'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-e'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-m'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-s'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-p'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-p', 'a' * (MAX_SEED_PASSWORD_LENGTH + 1)], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-v', '-m'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-v', '-s'], ExitCode.ARGUMENTS)
        self.assert_program_error([self.SCRIPT, '-g', '-r', '-v'], ExitCode.ARGUMENTS)
        with TemporaryDirectory() as tmpdir:
            non_existing_filepath = os.path.join(tmpdir, '__this_file_does_not_exist__')
            self.assert_program_error([self.SCRIPT, '-v', '-m', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-v', '-s', non_existing_filepath], ExitCode.ARGUMENTS)

            self.assert_program_error([self.SCRIPT, '-g', '-e', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-g', '-m', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-g', '-s', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-g', '-e', non_existing_filepath, '-m', non_existing_filepath],
                                      ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-g', '-m', non_existing_filepath, '-s', non_existing_filepath],
                                      ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-g', '-e', non_existing_filepath, '-s', non_existing_filepath],
                                      ExitCode.ARGUMENTS)

            self.assert_program_error([self.SCRIPT, '-r', '-e', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-r', '-m', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-r', '-s', non_existing_filepath], ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-r', '-e', non_existing_filepath, '-m', non_existing_filepath],
                                      ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-r', '-m', non_existing_filepath, '-s', non_existing_filepath],
                                      ExitCode.ARGUMENTS)
            self.assert_program_error([self.SCRIPT, '-r', '-e', non_existing_filepath, '-s', non_existing_filepath],
                                      ExitCode.ARGUMENTS)

    def test_arguments_ok_terminated(self):
        """correct argument resulting in termination"""
        self.assert_program_success([self.SCRIPT, '-h'])
        self.assert_program_success([self.SCRIPT, '--help'])
        self.assert_program_success([self.SCRIPT, '-V'])
        self.assert_program_success([self.SCRIPT, '--version'])

    def test_arguments_EX_NOINPUT(self):
        """input files don't exist"""
        with TemporaryDirectory() as tmpdir:
            non_existing_filepath = os.path.join(tmpdir, '__this_file_does_not_exist__')
            self.assert_program_error([self.SCRIPT, '-g',
                                       '-e', non_existing_filepath,
                                       '-m', non_existing_filepath,
                                       '-s', non_existing_filepath], ExitCode.EX_NOINPUT)
            self.assert_program_error([self.SCRIPT, '-r',
                                       '-e', non_existing_filepath,
                                       '-m', non_existing_filepath,
                                       '-s', non_existing_filepath], ExitCode.EX_NOINPUT)
            self.assert_program_error(
                [self.SCRIPT, '-v', '-m', non_existing_filepath, '-s', non_existing_filepath],
                ExitCode.EX_NOINPUT)

            with open(os.path.join(tmpdir, '__this_file_exists__.txt'), 'w') as f:
                f.write('foo bar')
            self.assert_program_error([self.SCRIPT, '-v', '-m', non_existing_filepath, '-s', f.name],
                                      ExitCode.EX_NOINPUT)

    def test_generate(self):
        with TemporaryDirectory() as tmpdir:
            for test_vector in TREZOR_TEST_VECTORS['english']:
                for io_format in Config.Format:  # type: Config.Format
                    with self.subTest(entropy=test_vector[0]):
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        entropy_path = os.path.join(tmpdir, '__entropy__')
                        with open(entropy_path, io_format.write_mode) as entropy_file:
                            entropy_file.write(
                                unhexlify(test_vector[0]) if io_format is Config.Format.BINARY else test_vector[0])
                        self.assert_program([self.SCRIPT, '-g', '--format', io_format.value, '-p', TREZOR_PASSWORD,
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
                            self.assertEqual(test_vector[2], seed)
                        with open(mnemonic_path, 'r') as mnemonic_file:
                            self.assertEqual(test_vector[1], mnemonic_file.read())

    def test_generate_invalid_entropy(self):
        with TemporaryDirectory() as tmpdir:
            for entropy, io_format, stderr in get_invalid_entropies():
                with self.subTest(entropy=entropy, io_format=io_format):
                    seed_path = os.path.join(tmpdir, '__seed__')
                    mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                    entropy_path = os.path.join(tmpdir, '__entropy__')
                    with open(entropy_path, io_format.write_mode) as entropy_file:
                        entropy_file.write(entropy)
                    self.assert_program([self.SCRIPT, '-g', '--format', io_format.value,
                                         '-e', entropy_path,
                                         '-m', mnemonic_path,
                                         '-s', seed_path], ExitCode.EX_DATAERR,
                                        stdout_check='',
                                        stderr_check=stderr)

    def test_recover(self):
        with TemporaryDirectory() as tmpdir:
            for test_vector in TREZOR_TEST_VECTORS['english']:
                for io_format in Config.Format:  # type: Config.Format
                    with self.subTest(mnemonic=test_vector[1]):
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        entropy_path = os.path.join(tmpdir, '__entropy__')
                        with open(mnemonic_path, 'w') as mnemonic_file:
                            mnemonic_file.write(test_vector[1])
                        self.assert_program([self.SCRIPT, '-r', '--format', io_format.value, '-p', TREZOR_PASSWORD,
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
                            self.assertEqual(test_vector[2], seed)
                        with open(entropy_path, io_format.read_mode) as entropy_file:
                            content = entropy_file.read()
                            if io_format is Config.Format.BINARY:
                                entropy = str(hexlify(content), 'ascii')
                            self.assertEqual(test_vector[0], entropy)

    def test_recover_invalid_mnemonic(self):
        with TemporaryDirectory() as tmpdir:
            for mnemonic, stderr in get_invalid_mnemonics():
                with self.subTest(mnemonic=mnemonic):
                    seed_path = os.path.join(tmpdir, '__seed__')
                    mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                    entropy_path = os.path.join(tmpdir, '__entropy__')
                    with open(mnemonic_path, 'w') as mnemonic_file:
                        mnemonic_file.write(mnemonic)
                    self.assert_program([self.SCRIPT, '-r',
                                         '-e', entropy_path,
                                         '-m', mnemonic_path,
                                         '-s', seed_path], ExitCode.EX_DATAERR,
                                        stdout_check='',
                                        stderr_check=stderr)

    def test_verify(self):
        with TemporaryDirectory() as tmpdir:
            for test_vector in TREZOR_TEST_VECTORS['english']:
                for io_format in Config.Format:  # type: Config.Format
                    with self.subTest(mnemonic=test_vector[1], seed=test_vector[2]):
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        with open(mnemonic_path, 'w') as mnemonic_file:
                            mnemonic_file.write(test_vector[1])
                        with open(seed_path, io_format.write_mode) as seed_file:
                            seed_file.write(
                                unhexlify(test_vector[2]) if io_format is Config.Format.BINARY else test_vector[2])
                        self.assert_program([self.SCRIPT, '-v', '--format', io_format.value, '-p', TREZOR_PASSWORD,
                                             '-m', mnemonic_path,
                                             '-s', seed_path], ExitCode.EX_OK,
                                            stdout_check='Seeds match.\n',
                                            stderr_check='')

    def test_verify_seeds_do_not_match(self):
        # valid mnemonic and valid seeds, but seeds and mnemonic do not match
        mnemonic = TREZOR_TEST_VECTORS['english'][0][1]
        valid_seeds = [
            (unhexlify(TREZOR_TEST_VECTORS['english'][1][2]), Config.Format.BINARY),
            (TREZOR_TEST_VECTORS['english'][2][2], Config.Format.TEXT_HEXADECIMAL),
        ]
        with TemporaryDirectory() as tmpdir:
            for seed, io_format in valid_seeds:
                with self.subTest(mnemonic=mnemonic, seed=seed, io_format=io_format):
                    seed_path = os.path.join(tmpdir, '__seed__')
                    mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                    with open(mnemonic_path, 'w') as mnemonic_file:
                        mnemonic_file.write(mnemonic)
                    with open(seed_path, io_format.write_mode) as seed_file:
                        seed_file.write(seed)
                    self.assert_program([self.SCRIPT, '-v', '--format', io_format.value,
                                         '-m', mnemonic_path,
                                         '-s', seed_path], ExitCode.SEEDS_DO_NOT_MATCH,
                                        stdout_check='',
                                        stderr_check='Seeds do not match.\n')

    def test_verify_invalid_mnemonic(self):
        valid_seeds = [
            (unhexlify(VALID_SEED_HEX_TREZOR), Config.Format.BINARY),
            (VALID_SEED_HEX_TREZOR, Config.Format.TEXT_HEXADECIMAL),
        ]
        with TemporaryDirectory() as tmpdir:
            for seed, io_format in valid_seeds:
                for mnemonic, stderr in get_invalid_mnemonics():
                    with self.subTest(mnemonic=mnemonic, seed=seed, io_format=io_format):
                        seed_path = os.path.join(tmpdir, '__seed__')
                        mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                        with open(mnemonic_path, 'w') as mnemonic_file:
                            mnemonic_file.write(mnemonic)
                        with open(seed_path, io_format.write_mode) as seed_file:
                            seed_file.write(seed)
                        self.assert_program([self.SCRIPT, '-v', '--format', io_format.value,
                                             '-m', mnemonic_path,
                                             '-s', seed_path], ExitCode.EX_DATAERR,
                                            stdout_check='',
                                            stderr_check=stderr)

    def test_verify_invalid_seed(self):
        with TemporaryDirectory() as tmpdir:
            for seed, io_format, stderr in get_invalid_seeds():
                with self.subTest(mnemonic=VALID_MNEMONIC_PHRASE_TREZOR, seed=seed, io_format=io_format):
                    seed_path = os.path.join(tmpdir, '__seed__')
                    mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                    with open(mnemonic_path, 'w') as mnemonic_file:
                        mnemonic_file.write(VALID_MNEMONIC_PHRASE_TREZOR)
                    with open(seed_path, io_format.write_mode) as seed_file:
                        seed_file.write(seed)
                    self.assert_program([self.SCRIPT, '-v', '--format', io_format.value,
                                         '-m', mnemonic_path,
                                         '-s', seed_path], ExitCode.EX_DATAERR,
                                        stdout_check='',
                                        stderr_check=stderr)

    def test_verify_missing_seed_file(self):
        with TemporaryDirectory() as tmpdir:
            non_existing_filepath = os.path.join(tmpdir, '__this_file_does_not_exist__')
            for io_format in Config.Format:
                mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                with open(mnemonic_path, 'w') as mnemonic_file:
                    mnemonic_file.write(VALID_MNEMONIC_PHRASE_TREZOR)
                self.assert_program([self.SCRIPT, '-v', '--format', io_format.value,
                                     '-m', mnemonic_path,
                                     '-s', non_existing_filepath], ExitCode.EX_NOINPUT,
                                    stdout_check='',
                                    stderr_check=None)

    def test_verify_missing_mnemonic_file(self):
        valid_seeds = [
            (unhexlify(VALID_SEED_HEX_TREZOR), Config.Format.BINARY),
            (VALID_SEED_HEX_TREZOR, Config.Format.TEXT_HEXADECIMAL),
        ]
        with TemporaryDirectory() as tmpdir:
            for seed, io_format in valid_seeds:
                seed_path = os.path.join(tmpdir, '__seed__')
                mnemonic_path = os.path.join(tmpdir, '__mnemonic__')
                with open(seed_path, io_format.write_mode) as seed_file:
                    seed_file.write(seed)
                self.assert_program([self.SCRIPT, '-v', '--format', io_format.value,
                                     '-m', mnemonic_path,
                                     '-s', seed_path], ExitCode.EX_NOINPUT,
                                    stdout_check='',
                                    stderr_check=None)
