"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import hashlib
import logging
import os
from typing import Dict, List, Tuple

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

def __get_dictionary() -> Tuple[List[str], Dict[str, int]]:
    """Load the dictionary.
    Currently uses 1 default dictionary with English words.
    # TODO Should we support multiple dictionaries for various languages?
    :raises FileNotFoundError: on missing file
    :raises ValueError: on invalid dictionary
    :rtype: Tuple[List[str], Dict[str, int]]
    :return: List and dictionary of words

    """
    l = []
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'english.txt'), 'r') as f:
        for i in range(2048):
            l.append(next(f).strip())
            if len(l[-1]) > 16 or len(l[-1].split()) != 1:
                raise ValueError('invalid dictionary')
        try:
            next(f)
        except StopIteration:
            pass
        else:
            raise ValueError('invalid dictionary')

    d = {l[i]: i for i in range(len(l))}
    return (l, d)


def __get_entropy_checksum(entropy: bytes, length: int) -> int:
    """Calculate entropy checksum of set length
    :rtype: int
    :return: checksum
    """
    entropy_hash = hashlib.sha256(entropy).digest()
    return int.from_bytes(entropy_hash, byteorder='big') >> 256 - length
    

def _entropy2mnemonic(entropy: bytes) -> str:
    """Convert entropy to mnemonic phrase using dictionary.
    :rtype: str
    :return: Mnemonic phrase

    > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
    'Checksum is computed using first ENT/32 bits of SHA256 hash. Concatenated bits are split
    into groups of 11 bits, each encoding a number from 0-2047, serving as an index into a
    wordlist.'
    """
    word_list, _ = __get_dictionary()
    shift = len(entropy) // 4
    checksum = __get_entropy_checksum(entropy, shift)

    # Concatenated bits representing the indexes
    indexes_bin = (int.from_bytes(entropy, byteorder='big') << shift) | checksum

    # List of indexes, number of which is MS = (ENT + CS) / 11 == shift * 3
    indexes = [(indexes_bin >> i * 11) & 2047 for i in reversed(range(shift * 3))]

    words = [word_list[i] for i in indexes]
    return ' '.join(words)


def _mnemonic2entropy(mnemonic: str) -> bytes:
    """Convert mnemonic phrase to entropy using dictionary.
    :raises ValueError: on invalid parameters
    :rtype: bytes
    :return: Entropy
    """
    if not isinstance(mnemonic, str):
        raise ValueError('invalid mnemonic')
    
    words = mnemonic.split()
    l = len(words)
    if not l in (12, 15, 18, 21, 24):
        raise ValueError('invalid mnemonic')

    _, word_dict = __get_dictionary()
    try:
        indexes = [word_dict[word] for word in words]
    except KeyError:
        raise ValueError('invalid mnemonic')

    # Concatenate indexes into single 
    indexes_bin = sum([indexes[-i - 1] << i * 11 for i in reversed(range(l))])

    # Number of bits entropy is shifted by
    shift = l * 11 // 32

    checksum = indexes_bin & (pow(2, shift) - 1)
    entropy_bin =  indexes_bin >> shift
    entropy = entropy_bin.to_bytes((l * 11 - shift) // 8, byteorder='big')

    # Check correctness
    check = __get_entropy_checksum(entropy, shift)
    if check != checksum:
        raise ValueError('invalid mnemonic')
    
    return entropy


def __is_valid_entropy(entropy: bytes) -> bool:
    """Check whether provided bytes represent a valid entropy according to BIP39.
    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

    > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is
    > improved but the sentence length increases. We refer to the initial entropy length as ENT.
    > The allowed size of ENT is 128-256 bits.
    > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
    """
    return len(entropy) in list(range(16, 32+1, 4))


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
    :raises ValueError: on invalid parameters
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
    :raises ValueError: on invalid parameters
    :rtype: Tuple[bytes, bytes]
    :return: Two item tuple where first is initial entropy and second is seed.
    """
    entropy = __mnemonic2entropy(mnemonic)
    seed = __generate_seed(mnemonic, seed_password)
    return entropy, seed


def verify(mnemonic: str, expected_seed: bytes, seed_password: str = '') -> bool:
    """Verify whether mnemonic phrase matches with expected seed.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: bool
    :return: True if provided phrase generates expected seed, False otherwise.
    """
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
