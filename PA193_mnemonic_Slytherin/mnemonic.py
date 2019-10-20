"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import hmac
import logging
from typing import Tuple
from hashlib import pbkdf2_hmac

__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)

PBKDF2_ROUNDS = 2048
SEED_LEN = 64


def _generate_seed(mnemonic: str, seed_password: str = '') -> bytes:
    """Generate seed from provided mnemonic phrase.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :rtype: bytes
    :return: Seed
    """
    # the encoding of both inputs should be UTF-8 NFKD
    mnemonic = mnemonic.encode()  # encoding string into bytes, UTF-8 by default
    passphrase = "mnemonic" + seed_password
    passphrase = passphrase.encode()
    return pbkdf2_hmac('sha512', mnemonic, passphrase, PBKDF2_ROUNDS, SEED_LEN)


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


def is_valid_entropy(entropy: bytes) -> bool:
    """Check whether provided bytes represent a valid entropy according to BIP39.
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

    > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is
    > improved but the sentence length increases. We refer to the initial entropy length as ENT.
    > The allowed size of ENT is 128-256 bits.
    > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
    """
    return len(entropy) in list(range(16, 32+1, 4))


def is_valid_mnemonic(mnemonic: str) -> bool:
    """Check whether provided string represents a valid mnemonic phrase based on current dictionary.
    Currently uses 1 default dictionary with English words.
    # TODO Should we support multiple dictionaries for various languages?
    """
    raise NotImplementedError()


def is_valid_seed(seed: bytes) -> bool:
    """Check whether provided bytes represent a valid seed.
    """
    return isinstance(seed, bytes) and len(seed) == SEED_LEN


def _secure_seed_compare(expected_seed: bytes, actual_seed: bytes) -> bool:
    """Compare provided seeds in constant time to prevent timing attacks.
    :raises TypeError: if parameters are not bytes-like objects
    :rtype: bool
    :return: True if seeds are the same, False otherwise.
    """
    # > hmac.compare_digest` uses an approach designed to prevent timing
    # > analysis by avoiding content-based short circuiting behaviour, making
    #  > it appropriate for cryptography
    # > https://docs.python.org/3.7/library/hmac.html#hmac.compare_digest
    #
    # > Note: If a and b are of different lengths, or if an error occurs,
    # > a timing attack could theoretically reveal information about the types
    #  > and lengths of a and b—but not their values.
    #
    # Type and length of seeds is known to the attacker, but not the value of expected seed.
    if not (isinstance(expected_seed, bytes) and isinstance(actual_seed, bytes)):
        # Function `hmac.compare_digest` accepts strings & bytes and raises TypeError
        # for other types. It would accept two strings, but we accept only two
        # bytes-like objects, therefore we raise TypeError here.
        raise TypeError('a bytes-like object is required')
    return hmac.compare_digest(expected_seed, actual_seed)


def generate(entropy: bytes, seed_password: str = '') -> Tuple[str, bytes]:
    """Generate mnemonic phrase and seed based on provided entropy.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: Tuple[str, bytes]
    :return: Two item tuple where first is mnemonic phrase and second is seed.
    """
    if not is_valid_entropy(entropy):
        raise ValueError('invalid entropy')

    mnemonic = __entropy2mnemonic(entropy)
    seed = _generate_seed(mnemonic, seed_password)
    return mnemonic, seed


def recover(mnemonic: str, seed_password: str = '') -> Tuple[bytes, bytes]:
    """ Recover initial entropy and seed from provided mnemonic phrase.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: Tuple[bytes, bytes]
    :return: Two item tuple where first is initial entropy and second is seed.
    """
    if not is_valid_mnemonic(mnemonic):
        raise ValueError('invalid mnemonic')

    entropy = __mnemonic2entropy(mnemonic)
    seed = _generate_seed(mnemonic, seed_password)
    return entropy, seed


def verify(mnemonic: str, expected_seed: bytes, seed_password: str = '') -> bool:
    """Verify whether mnemonic phrase matches with expected seed.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: bool
    :return: True if provided phrase generates expected seed, False otherwise.
    """
    if not is_valid_mnemonic(mnemonic):
        raise ValueError('invalid mnemonic')
    if not is_valid_seed(expected_seed):
        raise ValueError('invalid expected_seed')

    generated_seed = _generate_seed(mnemonic, seed_password)
    return _secure_seed_compare(expected_seed, generated_seed)
