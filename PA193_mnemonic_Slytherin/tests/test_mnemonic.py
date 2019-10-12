from unittest import TestCase

from PA193_mnemonic_Slytherin.mnemonic import do_some_work, _secure_seed_compare


class TestDoSomeWork(TestCase):
    """Placeholder for initial code structure."""

    def test_do_some_work(self):
        """Placeholder for initial code structure."""
        self.assertTrue(do_some_work(1))
        self.assertFalse(do_some_work(123))


class TestMnemonicInternal(TestCase):
    def test_secure_seed_compare(self):
        seed = b'\x27\x4d\xdc\x52\x58\x02\xf7\xc8\x28\xd8\xef\x7d\xdb\xcd\xc5' \
               b'\x30\x4e\x87\xac\x35\x35\x91\x36\x11\xfb\xbf\xa9\x86\xd0\xc9' \
               b'\xe5\x47\x6c\x91\x68\x9f\x9c\x8a\x54\xfd\x55\xbd\x38\x60\x6a' \
               b'\xa6\xa8\x59\x5a\xd2\x13\xd4\xc9\xc9\xf9\xac\xa3\xfb\x21\x70' \
               b'\x69\xa4\x10\x28'
        self.assertTrue(_secure_seed_compare(seed, seed))
        self.assertTrue(_secure_seed_compare(b'', b''))
        self.assertFalse(_secure_seed_compare(seed, b'\x00'))
        self.assertFalse(_secure_seed_compare(b'\x00', seed))
        self.assertFalse(_secure_seed_compare(seed, b''))
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            _secure_seed_compare(seed, None)
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            _secure_seed_compare(None, seed)
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            _secure_seed_compare('text', 'text')
