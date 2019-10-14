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
from tempfile import TemporaryDirectory

from PA193_mnemonic_Slytherin.mnemoniccli import ExitCode


class TestMain(unittest.TestCase):
    """Integration tests for CLI tool."""
    def setUp(self):
        self.timeout = 5  # seconds until we terminate the program
        self.cli_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')

    def assert_argument_error(self, args):
        cli = subprocess.run(args, cwd=self.cli_dir, capture_output=True, timeout=self.timeout, shell=True)
        self.assertEqual(b'', cli.stdout)
        self.assertNotEqual(b'', cli.stderr)
        self.assertEqual(ExitCode.ARGUMENTS.value, cli.returncode)

    def assert_argument_ok_terminated(self, args):
        cli = subprocess.run(args, cwd=self.cli_dir, capture_output=True, timeout=self.timeout, shell=True)
        self.assertNotEqual(b'', cli.stdout)
        self.assertEqual(b'', cli.stderr)
        self.assertEqual(ExitCode.EX_OK.value, cli.returncode)

    def test_arguments_error(self):
        """invalid arguments"""
        self.assert_argument_error(['mnemoniccli.py'])
        self.assert_argument_error(['mnemoniccli', '-ll', 'FOO'])
        self.assert_argument_error(['mnemoniccli', '-g'])
        self.assert_argument_error(['mnemoniccli', '-r'])
        self.assert_argument_error(['mnemoniccli', '-v'])
        self.assert_argument_error(['mnemoniccli', '-g', '-r', '-v'])

    def test_arguments_ok_terminated(self):
        """correct argument resulting in termination"""
        self.assert_argument_ok_terminated(['mnemoniccli', '-h'])
        self.assert_argument_ok_terminated(['mnemoniccli', '--help'])
        self.assert_argument_ok_terminated(['mnemoniccli', '-V'])
        self.assert_argument_ok_terminated(['mnemoniccli', '--version'])

    def test_arguments_error_file_path(self):
        """input files don't exist"""
        with TemporaryDirectory() as tmpdir:
            non_existing_filepath = os.path.join(tmpdir, '__this_file_does_not_exist__')
            self.assert_argument_error(['mnemoniccli', '-g', '-e', non_existing_filepath])
            self.assert_argument_error(['mnemoniccli', '-r', '-m', non_existing_filepath])
            self.assert_argument_error(['mnemoniccli', '-v', '-m', non_existing_filepath, '-s', non_existing_filepath])

            with open(os.path.join(tmpdir, '__this_file_exists__.txt'), 'w') as f:
                f.write('foo bar')
            self.assert_argument_error(['mnemoniccli', '-v', '-m', f.name, '-s', non_existing_filepath])
            self.assert_argument_error(['mnemoniccli', '-v', '-m', non_existing_filepath, '-s', f.name])


if __name__ == '__main__':
    unittest.main()
