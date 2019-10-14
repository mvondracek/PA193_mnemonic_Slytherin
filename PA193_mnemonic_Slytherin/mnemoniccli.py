#!/usr/bin/env python3
"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import argparse
import logging
import os
import sys
import warnings
from enum import Enum, unique
from pprint import saferepr
from typing import Sequence

from PA193_mnemonic_Slytherin import do_some_work

__version__ = '0.1.0'
__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)


@unique
class ExitCode(Enum):
    """
    Return codes.
    Some are inspired by sysexits.h.
    """
    EX_OK = 0
    """Program terminated successfully."""

    UNKNOWN_FAILURE = 1
    """Program terminated due to unknown error."""

    ARGUMENTS = 2
    """Incorrect or missing arguments provided."""

    EX_UNAVAILABLE = 69
    """Required program or file does not exist."""

    EX_NOPERM = 77
    """Permission denied."""

    KEYBOARD_INTERRUPT = 130
    """Program received SIGINT."""


def cli_entry_point():
    try:
        exit_code = main(sys.argv)
    except KeyboardInterrupt:
        print('Stopping.')
        logger.warning('received KeyboardInterrupt, stopping')
        sys.exit(ExitCode.KEYBOARD_INTERRUPT.value)
    except Exception as e:
        logger.critical(str(e) + ' ' + saferepr(e))
        print(str(e), file=sys.stderr)
        sys.exit(ExitCode.UNKNOWN_FAILURE.value)
    else:
        sys.exit(exit_code.value)


def main(argv) -> ExitCode:
    logging.captureWarnings(True)
    warnings.simplefilter('always', ResourceWarning)

    config = Config.parse_args(argv[1:])  # argv[0] is program name
    # On error with parsing argument, program was terminated by `Config.parse_args` with exit code 2 corresponding to
    # `ExitCode.ARGUMENTS`. If arguments contained -h/--help or -V/--version, program was terminated wtih exit code 0,
    # which corresponds to `ExitCode.E_OK`
    if config.logging_level:
        logging.basicConfig(format='%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s',
                            level=config.logging_level)
    else:
        logging.disable(logging.CRITICAL)
    logger.debug('Config parsed from args.')

    do_some_work(1)

    logger.debug('exit code: {} {}'.format(ExitCode.EX_OK.name, ExitCode.EX_OK.value))
    return ExitCode.EX_OK


class Config(object):
    @unique
    class Format(Enum):
        """Formats for reading and writing entropy, seed, and mnemonic phrase."""
        BINARY = 'bin'
        TEXT_HEXADECIMAL = 'hex'

    PROGRAM_NAME = 'mnemoniccli'
    PROGRAM_DESCRIPTION = 'BIP39 Mnemonic Phrase Generator and Verifier'
    LOGGING_LEVELS_DICT = {'debug': logging.DEBUG,
                           'warning': logging.WARNING,
                           'info': logging.INFO,
                           'error': logging.ERROR,
                           'critical': logging.ERROR,
                           'disabled': None,  # logging disabled
                           }
    LOGGING_LEVEL_DEFAULT = 'disabled'

    def __init__(self,
                 logging_level: int,
                 entropy_filepath: str,
                 seed_filepath: str,
                 mnemonic_filepath: str,
                 format_: Format,
                 password: str,
                 generate_: bool,
                 recover_: bool,
                 verify_: bool,
                 ):
        self.logging_level = logging_level
        self.entropy_filepath = entropy_filepath
        self.seed_filepath = seed_filepath
        self.mnemonic_filepath = mnemonic_filepath
        self.format = format_
        self.password = password
        self.generate = generate_
        self.recover = recover_
        self.verify = verify_

    @classmethod
    def init_parser(cls) -> argparse.ArgumentParser:
        """
        Initialize argument parser.
        :rtype: argparse.ArgumentParser
        :return: initialized parser
        """
        parser = argparse.ArgumentParser(
            prog=cls.PROGRAM_NAME,
            description=cls.PROGRAM_DESCRIPTION,
            epilog='Team Slytherin: @sobuch, @lsolodkova, @mvondracek.\n'
                   'Secure Coding Principles and Practices (PA193)\n'
                   'Faculty of Informatics (FI)\n'
                   'Masaryk University (MU)'
        )
        parser.add_argument('-V', '--version', action='version', version='%(prog)s {}'.format(__version__))
        parser.add_argument('-ll', '--logging-level',
                            # NOTE: The type is called before check against choices. In order to display logging level
                            # names as choices, name to level int value conversion cannot be done here. Conversion is
                            # done after parser call in `self.parse_args`.
                            default=cls.LOGGING_LEVEL_DEFAULT,
                            choices=cls.LOGGING_LEVELS_DICT,
                            help='select logging level (default: %(default)s)'
                            )
        parser.add_argument('-e', '--entropy',
                            help='path to file with entropy, input/output depends on action,',
                            metavar='FILE'
                            )
        parser.add_argument('-s', '--seed',
                            help='path to file with seed, input/output depends on action,',
                            metavar='FILE'
                            )
        parser.add_argument('-m', '--mnemonic',
                            help='path to file with mnemonic, input/output depends on action,',
                            metavar='FILE'
                            )
        parser.add_argument('-f', '--format',
                            default=cls.Format.TEXT_HEXADECIMAL.value,
                            choices={f.value: f for f in cls.Format},
                            help='select input and output format (default: %(default)s)'
                            )
        parser.add_argument('-p', '--password',
                            help='password for protection of seed',
                            default=''
                            )
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-g', '--generate',
                           action='store_true',
                           help='generate seed and mnemonic phrase from entropy'
                           )
        group.add_argument('-r', '--recover',
                           action='store_true',
                           help='recover entropy and seed from mnemonic phrase'
                           )
        group.add_argument('-v', '--verify',
                           action='store_true',
                           help='verify if provided phrase generates expected seed'
                           )
        return parser

    @classmethod
    def parse_args(cls, args: Sequence[str]):
        """Parse command line arguments and store checked and converted values in Config object.

        According to default behaviour of `argparse.ArgumentParser`, this method terminates
        program with exit code 2 (corresponding to `ExitCode.ARGUMENTS`) if passed arguments are
        invalid. If arguments contain -h/--help or -V/--version, program is terminated with exit
        code 0 (corresponding to `ExitCode.E_OK`).
        :type args: Sequence[str]
        :param args: argument strings
        """
        parser = cls.init_parser()  # type: argparse.ArgumentParser
        # NOTE: Call to parse_args with namespace=self does not set logging_level with default value, if argument is not
        # in provided args.
        parsed_args = parser.parse_args(args=args)
        # basic input file path check
        if parsed_args.generate:
            if not parsed_args.entropy:
                parser.error('argument entropy is required with action `generate`'.format(parsed_args.entropy))
            if not os.path.isfile(parsed_args.entropy):
                # TODO do not check `isfile` here, try to open it later and if it fails, termiante with EX_NOINPUT
                parser.error('argument entropy: input file `{}` does not exist'.format(parsed_args.entropy))
        elif parsed_args.recover:
            if not parsed_args.mnemonic:
                parser.error('argument mnemonic is required with action `recover`'.format(parsed_args.entropy))
            if not os.path.isfile(parsed_args.mnemonic):
                # TODO do not check `isfile` here, try to open it later and if it fails, termiante with EX_NOINPUT
                parser.error('argument mnemonic: input file `{}` does not exist'.format(parsed_args.mnemonic))
        elif parsed_args.verify:
            if not parsed_args.mnemonic:
                parser.error('argument mnemonic is required with action `verify`'.format(parsed_args.entropy))
            if not parsed_args.seed:
                parser.error('argument seed is required with action `verify`'.format(parsed_args.entropy))
            if not os.path.isfile(parsed_args.mnemonic):
                # TODO do not check `isfile` here, try to open it later and if it fails, termiante with EX_NOINPUT
                parser.error('argument mnemonic: input file `{}` does not exist'.format(parsed_args.mnemonic))
            if not os.path.isfile(parsed_args.seed):
                # TODO do not check `isfile` here, try to open it later and if it fails, termiante with EX_NOINPUT
                parser.error('argument seed: input file `{}` does not exist'.format(parsed_args.seed))

        config = cls(
            # name to value conversion as noted in `self.init_parser`
            logging_level=cls.LOGGING_LEVELS_DICT[parsed_args.logging_level],
            entropy_filepath=parsed_args.entropy,
            mnemonic_filepath=parsed_args.mnemonic,
            seed_filepath=parsed_args.seed,
            format_=cls.Format(parsed_args.format),
            password=parsed_args.password,
            generate_=parsed_args.generate,
            recover_=parsed_args.recover,
            verify_=parsed_args.verify,
        )
        return config


if __name__ == '__main__':
    cli_entry_point()
