"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import logging
from typing import Tuple

__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)


def __generate_seed(mnemonic: str, seed_password: str = '') -> bytes:
    """Generate seed from provided mnemonic phrase.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :rtype: bytes
    :return: Seed
    """
    pass


# TODO: functions __entropy2mnemonic, __mnemonic2entropy, __is_valid_mnemonic work with dictionary, we could use single
#       object with this dictionary to prevent multiple file opening and reading and to support multiple dictionaries
#       for various languages.

# TODO Possible problem with dictionary:
# - file not found
# - no permissions for file
# - dictionary does not contain exactly 2048 lines
# - dictionary is too big (2048 lines OK, but too long words) like hundreds of MB...
# - every line has exactly 1 word (no whitespaces)

def __entropy2mnemonic(entropy: bytes) -> str:
    """Convert entropy to mnemonic phrase using dictionary.
    Currently uses 1 default dictionary with English words.
    # TODO Should we support multiple dictionaries for various languages?
    :rtype: str
    :return: Mnemonic phrase
    """
    pass


def __mnemonic2entropy(mnemonic: str) -> bytes:
    """Convert mnemonic phrase to entropy using dictionary.
    Currently uses 1 default dictionary with English words.
    # TODO Should we support multiple dictionaries for various languages?
    :rtype: bytes
    :return: Entropy
    """
    pass


def __is_valid_entropy(entropy: bytes) -> bool:
    """Check whether provided bytes represent a valid entropy according to BIP39.
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    """
    pass


def __is_valid_mnemonic(mnemonic: str) -> bool:
    """Check whether provided string represents a valid mnemonic phrase based on current dictionary.
    Currently uses 1 default dictionary with English words.
    # TODO Should we support multiple dictionaries for various languages?
    """
    pass


def __is_valid_seed(seed: bytes) -> bool:
    """Check whether provided bytes represent a valid seed.
    """
    pass


def _secure_seed_compare(expected_seed: bytes, actual_seed: bytes) -> bool:
    """Compare provided seeds in constant time to prevent timing attacks.
    :rtype: bool
    :return: True if seeds are the same, False otherwise.
    """
    pass


def generate(entropy: bytes, seed_password: str = '') -> Tuple[str, bytes]:
    """Generate mnemonic phrase and seed based on provided entropy.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :rtype: Tuple[str, bytes]
    :return: Two item tuple where first is mnemonic phrase and second is seed.
    """
    if not __is_valid_entropy(entropy):
        raise ValueError('invalid entropy')

    mnemonic = __entropy2mnemonic(entropy)
    seed = __generate_seed(mnemonic, seed_password)
    return mnemonic, seed


def recover(mnemonic: str, seed_password: str = '') -> Tuple[bytes, bytes]:
    """ Recover initial entropy and seed from provided mnemonic phrase.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :rtype: Tuple[bytes, bytes]
    :return: Two item tuple where first is initial entropy and second is seed.
    """
    if not __is_valid_mnemonic(mnemonic):
        raise ValueError('invalid mnemonic')

    entropy = __mnemonic2entropy(mnemonic)
    seed = __generate_seed(mnemonic, seed_password)
    return entropy, seed


def verify(mnemonic: str, expected_seed: bytes, seed_password: str = '') -> bool:
    """Verify whether mnemonic phrase matches with expected seed.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :rtype: bool
    :return: True if provided phrase generates expected seed, False otherwise.
    """
    if not __is_valid_mnemonic(mnemonic):
        raise ValueError('invalid mnemonic')
    if not __is_valid_seed(expected_seed):
        raise ValueError('invalid expected_seed')

    generated_seed = __generate_seed(mnemonic, seed_password)
    return _secure_seed_compare(expected_seed, generated_seed)


def do_some_work(param: int) -> bool:
    """Placeholder for initial code structure.
    :rtype: bool
    :return True if some work was successful, False otherwise.
    # TODO remove this placeholder as soon as we have some real tests.
    """
    return param == 1
