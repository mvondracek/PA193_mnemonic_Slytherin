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
import os
from unicodedata import normalize
from hashlib import sha256, sha512
from typing import Dict, List, Tuple

__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)


ENGLISH_DICTIONARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'english.txt')
PBKDF2_ROUNDS = 2048
SEED_LEN = 64


def _xor_byte_strings(b1: bytes, b2: bytes) -> bytes:
    """Function for XOR'ing two objects of byte type
    Reference implementation: https://en.wikipedia.org/wiki/XOR_cipher
    :rtype: bytes
    :return b1 XOR b2
    """
    return bytes([x ^ y for x, y in zip(b1, b2)])


def _pbkdf2_sha512(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Password Based Key Derivation Function
    https://en.wikipedia.org/wiki/PBKDF2
    Uses HMAC-SHA512, derived key length is 512 bit
    :rtype: bytes
    :return: key derived by PBKDF2 algorithm
    """
    # The first iteration of PRF uses Password as the PRF key
    # and Salt concatenated with i encoded as a big-endian
    # 32-bit integer as the input.
    u = hmac.new(password, salt + (1).to_bytes(4, byteorder='big'), digestmod=sha512).digest()
    f = u  # f is the xor (^) of c iterations of chained PRFs
    for i in range(1, iterations):
        u = hmac.new(password, u, digestmod=sha512).digest()
        f = _xor_byte_strings(f, u)
    return f


class dictionaryAccess:
    """Abstract class for classes requiring dictionary access
    """

    def __init__(self, file_path: str = ENGLISH_DICTIONARY_PATH):
        """Load the dictionary.
        Currently uses 1 default dictionary with English words.
        # TODO Should we support multiple dictionaries for various languages?
        :raises FileNotFoundError: on missing file
        :raises ValueError: on invalid dictionary
        :rtype: Tuple[List[str], Dict[str, int]]
        :return: List and dictionary of words
        """
        self._dict_list = []
        self._dict_dict = {}
        with open(file_path, 'r') as f:
            for i in range(2048):
                line = next(f).strip()
                if len(line) > 16 or len(line.split()) != 1:
                    raise ValueError('Cannot instantiate dictionary')
                self._dict_list.append(line)
                self._dict_dict[line] = i
            if f.read():
                raise ValueError('Cannot instantiate dictionary')


class Seed(bytes):
    """Class for seed representation.
    """

    def __init__(self, seed: bytes):
        """Check whether provided bytes represent a valid seed.
        :raises ValueError: on invalid parameters
        """
        if not isinstance(seed, bytes) or len(seed) != SEED_LEN:
            raise ValueError('Cannot instantiate seed')
        self = seed

    def __eq__(self, other: object) -> bool:
        """Compare seeds in constant time to prevent timing attacks.
        :rtype: bool
        :return: True if seeds are the same, False otherwise.
        """
        result = 0
        if not isinstance(other, Seed):
            result = 1
            s = self
        else:
            s = other
        for b1, b2 in zip(self, s):
            result |= b1 ^ b2
        return result == 0

    def __ne__(self, other: object) -> bool:
        """Compare seeds in constant time to prevent timing attacks.
        :rtype: bool
        :return: False if seeds are the same, True otherwise.
        """
        return not (self == other)


class Entropy(bytes, dictionaryAccess):
    """Class for entropy representation.
    """

    def __init__(self, entropy: bytes):
        """Check whether provided bytes represent a valid entropy according to BIP39.
        https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

        > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is
        > improved but the sentence length increases. We refer to the initial entropy length as ENT.
        > The allowed size of ENT is 128-256 bits.
        > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
        :raises ValueError: on invalid parameters
        """
        dictionaryAccess.__init__(self)

        if len(entropy) not in list(range(16, 32+1, 4)):
            raise ValueError('Cannot instantiate entropy')
        self = entropy

    def checksum(self, length: int) -> int:
        """Calculate entropy checksum of set length
        :rtype: int
        :return: checksum
        """
        entropy_hash = sha256(self).digest()
        return int.from_bytes(entropy_hash, byteorder='big') >> 256 - length

    def toMnemonic(self) -> 'Mnemonic':
        """Convert entropy to mnemonic phrase using dictionary.
        :rtype: Mnemonic
        :return: Mnemonic phrase

        > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
        'Checksum is computed using first ENT/32 bits of SHA256 hash. Concatenated bits are split
        into groups of 11 bits, each encoding a number from 0-2047, serving as an index into a
        wordlist.'
        """
        shift = len(self) // 4
        checksum = self.checksum(shift)

        # Concatenated bits representing the indexes
        indexes_bin = (int.from_bytes(self, byteorder='big') << shift) | checksum

        # List of indexes, number of which is MS = (ENT + CS) / 11 == shift * 3
        indexes = [(indexes_bin >> i * 11) & 2047 for i in reversed(range(shift * 3))]

        words = [self._dict_list[i] for i in indexes]
        return Mnemonic(' '.join(words))


class Mnemonic(str, dictionaryAccess):
    """Class for mnemonic representation.
    """

    def __init__(self, mnemonic: str):
        """Convert mnemonic phrase to entropy using dictionary to ensure its validity.
        :raises ValueError: on invalid parameters
        """
        dictionaryAccess.__init__(self)

        if not isinstance(mnemonic, str):
            raise ValueError('Cannot instantiate mnemonic')

        words = mnemonic.split()
        n_words = len(words)
        if n_words not in (12, 15, 18, 21, 24):
            raise ValueError('Cannot instantiate mnemonic')

        try:
            indexes = [self._dict_dict[word] for word in words]
        except KeyError:
            raise ValueError('Cannot instantiate mnemonic')

        # Concatenate indexes into single variable
        indexes_bin = sum([indexes[-i - 1] << i * 11 for i in reversed(range(n_words))])

        # Number of bits entropy is shifted by
        shift = n_words * 11 // 32

        checksum = indexes_bin & (pow(2, shift) - 1)
        entropy_bin = indexes_bin >> shift
        entropy = entropy_bin.to_bytes((n_words * 11 - shift) // 8, byteorder='big')

        self.__entropy = Entropy(entropy)
        # Check correctness
        if checksum != self.__entropy.checksum(shift):
            raise ValueError('Cannot instantiate mnemonic')
        self = mnemonic

    def toSeed(self, seed_password: str = '') -> Seed:
        """Generate seed from the mnemonic phrase.
        Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
        (empty string) by default.
        :raises ValueError: on invalid parameters
        :rtype: Seed
        :return: Seed
        """
        # the length of the password is bounded to 256
        if len(seed_password) > 256:
            raise ValueError('Password is too long')
        # the encoding of both inputs should be UTF-8 NFKD
        mnemonic = self.encode()  # encoding string into bytes, UTF-8 by default
        seed_password = normalize('NFKD', seed_password)
        passphrase = "mnemonic" + seed_password
        passphrase = passphrase.encode()
        return Seed(_pbkdf2_sha512(mnemonic, passphrase, PBKDF2_ROUNDS))

    def toEntropy(self) -> Entropy:
        """Generate entropy from the mnemonic phrase.
        :rtype: Entropy
        :return: entropy
        """
        return self.__entropy


def generate(entropy: Entropy, seed_password: str = '') -> Tuple[Mnemonic, Seed]:
    """Generate mnemonic phrase and seed based on provided entropy.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: Tuple[Mnemonic, Seed]
    :return: Two item tuple where first is mnemonic phrase and second is seed.
    """
    if not isinstance(entropy, Entropy):
        raise TypeError('Expected Entropy, got {}'.format(type(entropy)))
    if not isinstance(seed_password, str):
        raise TypeError('Expected str, got {}'.format(type(seed_password)))

    mnemonic = entropy.toMnemonic()
    seed = mnemonic.toSeed(seed_password)
    return mnemonic, seed


def recover(mnemonic: Mnemonic, seed_password: str = '') -> Tuple[Entropy, Seed]:
    """ Recover initial entropy and seed from provided mnemonic phrase.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: Tuple[Entropy, Seed]
    :return: Two item tuple where first is initial entropy and second is seed.
    """
    if not isinstance(mnemonic, Mnemonic):
        raise TypeError('Expected Mnemonic, got {}'.format(type(mnemonic)))
    if not isinstance(seed_password, str):
        raise TypeError('Expected str, got {}'.format(type(seed_password)))

    entropy = mnemonic.toEntropy()
    seed = mnemonic.toSeed(seed_password)
    return entropy, seed


def verify(mnemonic: Mnemonic, expected_seed: Seed, seed_password: str = '') -> bool:
    """Verify whether mnemonic phrase matches with expected seed.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: bool
    :return: True if provided phrase generates expected seed, False otherwise.
    """
    if not isinstance(expected_seed, Seed):
        raise TypeError('Expected Seed, got {}'.format(type(expected_seed)))
    if not isinstance(mnemonic, Mnemonic):
        raise TypeError('Expected Mnemonic, got {}'.format(type(mnemonic)))
    if not isinstance(seed_password, str):
        raise TypeError('Expected str, got {}'.format(type(seed_password)))

    generated_seed = mnemonic.toSeed(seed_password)
    return expected_seed == generated_seed
