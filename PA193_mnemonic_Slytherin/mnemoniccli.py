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
import sys
import warnings
from enum import Enum, unique
from pprint import saferepr
from typing import Sequence

import coloredlogs

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
    if config.logging_level:
        coloredlogs.install(level=config.logging_level)
    else:
        logging.disable(logging.CRITICAL)
    logger.debug('Config parsed from args.')

    do_some_work(1)

    logger.debug('exit code: {} {}'.format(ExitCode.EX_OK.name, ExitCode.EX_OK.value))
    return ExitCode.EX_OK


class Config(object):
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

    def __init__(self):
        self.logging_level = self.LOGGING_LEVELS_DICT[self.LOGGING_LEVEL_DEFAULT]  # type: int

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
        parser.add_argument('-v', '--version', action='version', version='%(prog)s {}'.format(__version__))
        parser.add_argument('-ll', '--logging-level',
                            # NOTE: The type is called before check against choices. In order to display logging level
                            # names as choices, name to level int value conversion cannot be done here. Conversion is
                            # done after parser call in `self.parse_args`.
                            default=cls.LOGGING_LEVEL_DEFAULT,
                            choices=cls.LOGGING_LEVELS_DICT,
                            help='select logging level (default: %(default)s)'
                            )
        return parser

    @classmethod
    def parse_args(cls, args: Sequence[str]):
        """
        Parse command line arguments and store checked and converted values in Config object.
        :type args: Sequence[str]
        :param args: argument strings
        """
        parser = cls.init_parser()  # type: argparse.ArgumentParser
        # NOTE: Call to parse_args with namespace=self does not set logging_level with default value, if argument is not
        # in provided args.
        parsed_args = parser.parse_args(args=args)
        config = cls()
        # name to value conversion as noted in `self.init_parser`
        config.logging_level = config.LOGGING_LEVELS_DICT[parsed_args.logging_level]
        return config


if __name__ == '__main__':
    cli_entry_point()
