"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import os
from binascii import unhexlify
from tempfile import TemporaryDirectory
from unittest import TestCase

from PA193_mnemonic_Slytherin.mnemonic import Entropy, Mnemonic, Seed, _DictionaryAccess
from PA193_mnemonic_Slytherin.mnemonic import generate, recover, verify

# Test vectors by Trezor. Organized as entropy, mnemonic, seed, xprv
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
TREZOR_PASSWORD = 'TREZOR'
# noinspection SpellCheckingInspection
TREZOR_TEST_VECTORS = {
    'english': [
        [
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",  # nopep8
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",  # nopep8
            "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"  # nopep8
        ],
        [
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",  # nopep8
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",  # nopep8
            "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"  # nopep8
        ],
        [
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",  # nopep8
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",  # nopep8
            "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"  # nopep8
        ],
        [
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",  # nopep8
            "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"  # nopep8
        ],
        [
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",  # nopep8
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",  # nopep8
            "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"  # nopep8
        ],
        [
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",  # nopep8
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",  # nopep8
            "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"  # nopep8
        ],
        [
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",  # nopep8
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",  # nopep8
            "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"  # nopep8
        ],
        [
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",  # nopep8
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",  # nopep8
            "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"  # nopep8
        ],
        [
            "0000000000000000000000000000000000000000000000000000000000000000",  # nopep8
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",  # nopep8
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",  # nopep8
            "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"  # nopep8
        ],
        [
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",  # nopep8
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",  # nopep8
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",  # nopep8
            "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"  # nopep8
        ],
        [
            "8080808080808080808080808080808080808080808080808080808080808080",  # nopep8
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",  # nopep8
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",  # nopep8
            "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"  # nopep8
        ],
        [
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # nopep8
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",  # nopep8
            "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"  # nopep8
        ],
        [
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",  # nopep8
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",  # nopep8
            "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"  # nopep8
        ],
        [
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",  # nopep8
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",  # nopep8
            "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"  # nopep8
        ],
        [
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",  # nopep8
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",  # nopep8
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",  # nopep8
            "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"  # nopep8
        ],
        [
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",  # nopep8
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",  # nopep8
            "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"  # nopep8
        ],
        [
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",  # nopep8
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",  # nopep8
            "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"  # nopep8
        ],
        [
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",  # nopep8
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",  # nopep8
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",  # nopep8
            "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"  # nopep8
        ],
        [
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",  # nopep8
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",  # nopep8
            "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"  # nopep8
        ],
        [
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",  # nopep8
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",  # nopep8
            "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"  # nopep8
        ],
        [
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",  # nopep8
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",  # nopep8
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",  # nopep8
            "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"  # nopep8
        ],
        [
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",  # nopep8
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",  # nopep8
            "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"  # nopep8
        ],
        [
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",  # nopep8
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",  # nopep8
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",  # nopep8
            "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"  # nopep8
        ],
        [
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",  # nopep8
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",  # nopep8
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",  # nopep8
            "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"  # nopep8
        ]
    ]
}


class TestPublicFunctions(TestCase):
    """Tests for public functions of mnemonic module.
    Tests for `generate`, `recover`, and `verify` are similar, but we want to
    test each function separately.
    TODO add testing for incorrect inputs
    """
    VALID_MNEMONIC = Mnemonic(TREZOR_TEST_VECTORS['english'][0][1])
    VALID_ENTROPY = Entropy(unhexlify(TREZOR_TEST_VECTORS['english'][0][0]))
    VALID_SEED = Seed(unhexlify(TREZOR_TEST_VECTORS['english'][0][2]))
    VALID_PASSWORD = TREZOR_PASSWORD
    TESTING_TYPES = [
        None,
        123,
        3.14,
        [None],
        (None, None),
        {'a': 1, 'b': None},
    ]

    def test_generate(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            mnemonic, seed = generate(Entropy(unhexlify(test_vector[0])), TREZOR_PASSWORD)
            self.assertEqual(Mnemonic(test_vector[1]), mnemonic)
            self.assertEqual(Seed(unhexlify(test_vector[2])), seed)

    def test_generate_invalid_arguments(self):
        # noinspection PyTypeChecker
        for test_entropy in self.TESTING_TYPES + ['some string']:
            with self.assertRaisesRegex(TypeError, 'argument `entropy` should be of type Entropy'):
                generate(test_entropy, self.VALID_PASSWORD)
        # noinspection PyTypeChecker
        for test_password in self.TESTING_TYPES + [b'\xff']:
            with self.assertRaisesRegex(TypeError, 'argument `seed_password` should be of type str'):
                generate(self.VALID_ENTROPY, test_password)

    def test_recover(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            entropy, seed = recover(Mnemonic(test_vector[1]), TREZOR_PASSWORD)
            self.assertEqual(Entropy(unhexlify(test_vector[0])), entropy)
            self.assertEqual(Seed(unhexlify(test_vector[2])), seed)

    def test_recover_invalid_arguments(self):
        # noinspection PyTypeChecker
        for test_mnemonic in self.TESTING_TYPES + ['some string', b'\xff']:
            with self.assertRaisesRegex(TypeError, 'argument `mnemonic` should be of type Mnemonic'):
                recover(test_mnemonic, self.VALID_PASSWORD)
        # noinspection PyTypeChecker
        for test_password in self.TESTING_TYPES + [b'\xff']:
            with self.assertRaisesRegex(TypeError, 'argument `seed_password` should be of type str'):
                recover(self.VALID_MNEMONIC, test_password)

    def test_verify(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            self.assertTrue(verify(Mnemonic(test_vector[1]), Seed(unhexlify(test_vector[2])), TREZOR_PASSWORD))

    def test_verify_invalid_arguments(self):
        # noinspection PyTypeChecker
        for test_mnemonic in self.TESTING_TYPES + ['some string', b'\xff']:
            with self.assertRaisesRegex(TypeError, 'argument `mnemonic` should be of type Mnemonic'):
                verify(test_mnemonic, self.VALID_SEED, self.VALID_PASSWORD)
        # noinspection PyTypeChecker
        for test_seed in self.TESTING_TYPES + ['some string']:
            with self.assertRaisesRegex(TypeError, 'argument `expected_seed` should be of type Seed'):
                verify(self.VALID_MNEMONIC, test_seed, self.VALID_PASSWORD)
        # noinspection PyTypeChecker
        for test_password in self.TESTING_TYPES + [b'\xff']:
            with self.assertRaisesRegex(TypeError, 'argument `seed_password` should be of type str'):
                verify(self.VALID_MNEMONIC, self.VALID_SEED, test_password)


# TODO add more tests (different from Trezor vector)
class TestMnemonic(TestCase):
    """Tests Mnemonic"""
    VALID_MNEMONIC_PHRASE = TREZOR_TEST_VECTORS['english'][0][1]

    def test___init__(self):
        whitespaces = ['\t', '\n', '\x0b', '\x0c', '\r', ' ', '\x85', '\xa0', '\u1680', '\u2000', '\u2001', '\u2002',
                       '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u2028',
                       '\u2029', '\u202f', '\u205f', '\u3000']
        for test_vector in TREZOR_TEST_VECTORS['english']:
            Mnemonic(test_vector[1])
            for whitespace in whitespaces:
                Mnemonic(whitespace + test_vector[1] + whitespace)

    def test___init___invalid_argument(self):
        for test_input in [
            None,
            1,
            b'\xff',
            b'text as bytes not str',
            ['text in a list'],
        ]:
            with self.subTest(test_input=test_input):
                with self.assertRaisesRegex(TypeError, r'argument `mnemonic` should be str'):
                    # noinspection PyTypeChecker
                    Mnemonic(test_input)  # type: ignore

        for test_input in [
            '',
            'abandon ' * 11,
            self.VALID_MNEMONIC_PHRASE + ' abandon',
        ]:
            with self.subTest(test_input=test_input):
                with self.assertRaisesRegex(ValueError, r'argument `mnemonic` has invalid number of words'):
                    Mnemonic(test_input)

        for test_input in [
            'test_ string_ not_ in_ dictionary_ test_ string_ not_ in_ dictionary_ test_ test_',
            'あいいここあくしんん ' * 12,
            'not_in_dictionary ' * 12,
        ]:
            with self.subTest(test_input=test_input):
                with self.assertRaisesRegex(ValueError, r'argument `mnemonic` contains word (.+) which is not in '
                                                        r'current dictionary'):
                    Mnemonic(test_input)

        for test_input in [
            'abandon ' * 12,
            ' '.join(self.VALID_MNEMONIC_PHRASE.split()[:-1] + [' abandon']),  # last word replaced
        ]:
            with self.subTest(test_input=test_input):
                with self.assertRaisesRegex(ValueError,
                                            r'argument `mnemonic` includes checksum \d+ different from computed \d+'):
                    Mnemonic(test_input)

    def test___init___too_long_str(self):
        """Too long mnemonic phrase."""
        with self.assertRaises(ValueError):
            Mnemonic('a' * 1024 * 1024 * 1024 * 2)  # 2 GB

    def test_checksum(self):
        # TODO Could we check `Mnemonic.checksum` without `Entropy.checksum`? See `TestEntropy.test_checksum`.
        for test_vector in TREZOR_TEST_VECTORS['english']:
            with self.subTest(mnemonic=test_vector[1]):
                entropy = Entropy(unhexlify(test_vector[0]))
                checksum = Mnemonic.checksum(test_vector[1])
                self.assertEqual(entropy.checksum(), checksum)

    def test_checksum_invalid_mnemonic(self):
        for test_input in [
            None,
            123,
            b'\xff',
            [None]
        ]:
            with self.assertRaisesRegex(TypeError, 'argument `mnemonic` should be str'):
                # noinspection PyTypeChecker
                Mnemonic.checksum(test_input)  # type: ignore

        for test_input in [
            '',
            'abandon ' * 11,
            self.VALID_MNEMONIC_PHRASE + ' abandon',
        ]:
            with self.assertRaisesRegex(ValueError, 'argument `mnemonic` has invalid number of words'):
                Mnemonic.checksum(test_input)

        for test_input in [
            'test_ string_ not_ in_ dictionary_ test_ string_ not_ in_ dictionary_ test_ test_',
            'あいいここあくしんん ' * 12,
            'not_in_dictionary ' * 12,
        ]:
            with self.subTest(test_input=test_input):
                with self.assertRaisesRegex(ValueError,
                                            r'argument `mnemonic` contains word (.+) which is not in '
                                            r'current dictionary'):
                    Mnemonic.checksum(test_input)

    def test_checksum_invalid_dictionary_file_path(self):
        for test_input in [
            None,
            123,
            b'\xff',
            [None]
        ]:
            with self.assertRaisesRegex(TypeError, 'argument `dictionary_file_path` should be str'):
                # noinspection PyTypeChecker
                Mnemonic.checksum(self.VALID_MNEMONIC_PHRASE, test_input)  # type: ignore

    def test_checksum_invalid_dictionary_words_on_line(self):
        with TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, '__dictionary_words_on_line__.txt'), 'w') as f:
                for i in range(2047):  # 2047 because we will write last line `multiple words on single line` separately
                    f.write('word_{}\n'.format(i))
                f.write('multiple words on single line\n')
            with self.assertRaisesRegex(ValueError, 'Cannot instantiate dictionary'):
                Mnemonic.checksum(self.VALID_MNEMONIC_PHRASE, dictionary_file_path=f.name)

    def test_checksum_invalid_dictionary_long_word(self):
        with TemporaryDirectory() as tmpdir:
            for word_lengths in [17, 18, 19]:
                with open(os.path.join(tmpdir, '__dictionary_long_word__.txt'), 'w') as f:
                    for i in range(2047):  # 2047 because we will write last line `multiple words on single line` separately
                        f.write('word_{}\n'.format(i))
                    f.write('a' * word_lengths + '\n')
                with self.assertRaisesRegex(ValueError, 'Cannot instantiate dictionary'):
                    Mnemonic.checksum(self.VALID_MNEMONIC_PHRASE, dictionary_file_path=f.name)

    def test_toSeed(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            with self.subTest(mnemonic=test_vector[1]):
                mnemonic = Mnemonic(test_vector[1])
                seed_expected = Seed(unhexlify(test_vector[2]))
                self.assertEqual(seed_expected, mnemonic.to_seed(TREZOR_PASSWORD))

    def test_toSeed_invalid_password(self):
        for password in [None, 1, ['text in array'], b'text as bytes']:
            with self.subTest(password=password):
                mnemonic = Mnemonic('abandon abandon abandon abandon abandon abandon'
                                    ' abandon abandon abandon abandon abandon about')
                with self.assertRaisesRegex(TypeError, r'argument `seed_password` should be str'):
                    # noinspection PyTypeChecker
                    mnemonic.to_seed(password)  # type: ignore

    def test_toEntropy(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            with self.subTest(mnemonic=test_vector[1]):
                mnemonic = Mnemonic(test_vector[1])
                entropy_expected = Entropy(unhexlify(test_vector[0]))
                self.assertEqual(entropy_expected, mnemonic.to_entropy())

    def test_toEntropy_deep_copy(self):
        m = Mnemonic('abandon abandon abandon abandon abandon abandon'
                     ' abandon abandon abandon abandon abandon about')
        self.assertIsNot(m.to_entropy(),
                         m.to_entropy())
        self.assertEqual(m.to_entropy(),
                         m.to_entropy())
        e_from_m = m.to_entropy()  # returns new Entropy

        self.assertIsNot(e_from_m.to_mnemonic(),
                         e_from_m.to_mnemonic())
        self.assertEqual(e_from_m.to_mnemonic(),
                         e_from_m.to_mnemonic())
        m_from_e_from_m = e_from_m.to_mnemonic()  # returns new Mnemonic
        self.assertIsNot(m_from_e_from_m, m)
        self.assertEqual(m_from_e_from_m, m)


class TestSeed(TestCase):
    """Tests Seed"""

    def setUp(self) -> None:
        self.seed_bytes_a1 = int.to_bytes(1, 64, 'little')
        self.seed_bytes_a2 = int.to_bytes(1, 64, 'little')
        self.assertEqual(self.seed_bytes_a1, self.seed_bytes_a2)
        self.assertIsNot(self.seed_bytes_a1, self.seed_bytes_a2)
        # `self.seed_bytes_a1`, `self.seed_bytes_a2` are not identical, but compare to same value
        self.seed_bytes_b = int.to_bytes(255, 64, 'little')

    def test___init__(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            Seed(unhexlify(test_vector[2]))

    def test___init___invalid_argument(self):
        test_cases_type = [None, '', '1234567890abcd', 'NonHexaString_!?', [b'']]
        for test in test_cases_type:
            with self.assertRaises(TypeError):
                # noinspection PyTypeChecker
                Seed(test)  # type: ignore

        test_cases_value = [b'', b'tooShort', b'63bytesLongSoExactlyOneByteShortOfBeingValidSoCloseYetSoFarSAD!',
                            b'soLongItHurtsHurDurBlaBlaButAnywayThisShouldFail123456789101112131415', 0, 123,
                            unhexlify(TREZOR_TEST_VECTORS['english'][0][2]) + b'almost_ok']
        for test in test_cases_value:
            with self.assertRaises(ValueError):
                Seed(test)

    def test___eq__(self):
        s1 = Seed(self.seed_bytes_a1)
        self.assertTrue(s1 == s1)
        self.assertTrue(Seed(self.seed_bytes_a1) == Seed(self.seed_bytes_a1))
        self.assertTrue(Seed(self.seed_bytes_a1) == Seed(self.seed_bytes_a2))
        self.assertFalse(Seed(self.seed_bytes_a1) == Seed(self.seed_bytes_b))
        self.assertFalse(s1 == [1, 2, 3])

    def test__ne__(self):
        s1 = Seed(self.seed_bytes_a1)
        self.assertFalse(s1 != s1)
        self.assertFalse(Seed(self.seed_bytes_a1) != Seed(self.seed_bytes_a1))
        self.assertFalse(Seed(self.seed_bytes_a1) != Seed(self.seed_bytes_a2))
        self.assertTrue(Seed(self.seed_bytes_a1) != Seed(self.seed_bytes_b))
        self.assertTrue(s1 != [1, 2, 3])


class TestEntropy(TestCase):
    """Tests Entropy"""

    def test___init__(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            Entropy(unhexlify(test_vector[0]))

    def test___init___invalid_argument(self):
        test_cases_type = [None, '', '1234567890abcd', 'NonHexaString_!?', [b'']]
        for test in test_cases_type:
            with self.assertRaises(TypeError):
                # noinspection PyTypeChecker
                Entropy(test)  # type: ignore

        test_cases_value = [b'', b'tooShort', b'Well26BytesIsNotGonnaCutIT', b'Not15neitherLol',
                            b'soLongItHurtsHurDurBlaBlaButAnywayThisShouldFail123456789101112131415', 0, 123,
                            unhexlify(TREZOR_TEST_VECTORS['english'][0][2]) + b'almost_ok']
        for test in test_cases_value:
            with self.assertRaises(ValueError):
                Entropy(test)

    def test_checksum(self):
        # TODO Could we check `Entropy.checksum` without `Mnemonic.checksum`? See `TestMnemonic.test_checksum`.
        for test_vector in TREZOR_TEST_VECTORS['english']:
            with self.subTest(entropy=test_vector[0]):
                checksum_from_mnemonic = Mnemonic.checksum(test_vector[1])
                entropy = Entropy(unhexlify(test_vector[0]))
                self.assertEqual(checksum_from_mnemonic, entropy.checksum())

    def test_toMnemonic(self):
        for test_vector in TREZOR_TEST_VECTORS['english']:
            entropy = Entropy(unhexlify(test_vector[0]))
            mnemonic_expected = Mnemonic(test_vector[1])
            self.assertEqual(mnemonic_expected, entropy.to_mnemonic())

    def test_toMnemonic_deep_copy(self):
        e = Entropy(unhexlify('00000000000000000000000000000000'))
        self.assertIsNot(e.to_mnemonic(),
                         e.to_mnemonic())
        self.assertEqual(e.to_mnemonic(),
                         e.to_mnemonic())
        m_from_e = e.to_mnemonic()  # returns new Mnemonic

        self.assertIsNot(m_from_e.to_entropy(),
                         m_from_e.to_entropy())
        self.assertEqual(m_from_e.to_entropy(),
                         m_from_e.to_entropy())
        e_from_m_from_e = m_from_e.to_entropy()  # returns new Entropy
        self.assertIsNot(e_from_m_from_e, e)
        self.assertEqual(e_from_m_from_e, e)


# noinspection PyPep8Naming
class Test_DictionaryAccess(TestCase):
    def test___init___invalid_file_path(self):
        for test_input in [
            None,
            123,
            b'\xff',
            [None]
        ]:
            with self.assertRaisesRegex(TypeError, 'argument `file_path` should be str'):
                # noinspection PyTypeChecker
                _DictionaryAccess(test_input)  # type: ignore

    def test___init___invalid_dictionary_words_on_line(self):
        with TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, '__dictionary_words_on_line__.txt'), 'w') as f:
                for i in range(
                        2047):  # 2047 because we will write last line `multiple words on single line` separately
                    f.write('word_{}\n'.format(i))
                f.write('multiple words on single line\n')
            with self.assertRaisesRegex(ValueError, 'Cannot instantiate dictionary'):
                _DictionaryAccess(f.name)

    def test___init___invalid_dictionary_long_word(self):
        with TemporaryDirectory() as tmpdir:
            for word_lengths in [17, 18, 19]:
                with open(os.path.join(tmpdir, '__dictionary_long_word__.txt'), 'w') as f:
                    for i in range(
                            2047):  # 2047 because we will write last line `multiple words on single line` separately
                        f.write('word_{}\n'.format(i))
                    f.write('a' * word_lengths + '\n')
                with self.assertRaisesRegex(ValueError, 'Cannot instantiate dictionary'):
                    _DictionaryAccess(f.name)
