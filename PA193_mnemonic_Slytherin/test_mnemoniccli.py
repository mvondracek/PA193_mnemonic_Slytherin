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
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from tempfile import TemporaryDirectory
from typing import Optional, List

from PA193_mnemonic_Slytherin.mnemoniccli import ExitCode, cli_entry_point


class TestMain(unittest.TestCase):
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
        if stdout_check is not None:
            self.assertEqual(stdout_check, cli.stdout)
        else:
            self.assertNotEqual('', cli.stdout)
        if stderr_check is not None:
            self.assertEqual(stderr_check, cli.stderr)
        else:
            self.assertNotEqual('', cli.stderr)
        self.assertEqual(exitcode.value, cli.returncode)

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

    def test_invalid_entropy(self):
        """Invalid input file with entropy
        > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is improved but
        > the sentence length increases. We refer to the initial entropy length as ENT. The allowed size of ENT
        > is 128-256 bits.
        > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
        """
        with TemporaryDirectory() as tmpdir:
            non_existing_filepath = os.path.join(tmpdir, '__this_file_does_not_exist__')
            # binary input file
            # basic byte of entropy for this test
            entropy_byte = b'\x01'
            valid_entropy_bytes_lengths = (16, 20, 24, 28, 32)
            for entropy_bytes_length in range(0, 40):
                if entropy_bytes_length in valid_entropy_bytes_lengths:
                    continue
                with self.subTest(entropy_bytes_length=entropy_bytes_length):
                    with open(os.path.join(tmpdir, '__entropy_binary__.dat'), 'wb') as f:
                        f.write(entropy_byte * entropy_bytes_length)
                    self.assert_program([self.SCRIPT, '-g', '--format', 'bin',
                                         '-e', f.name,
                                         '-m', non_existing_filepath,
                                         '-s', non_existing_filepath], ExitCode.EX_DATAERR,
                                        stdout_check='', stderr_check=None)
