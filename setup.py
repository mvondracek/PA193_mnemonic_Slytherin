#!/usr/bin/env python3
"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""

from setuptools import setup

__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='PA193_mnemonic_Slytherin',
    version='0.1.0',
    description='BIP39 Mnemonic Phrase Generator and Verifier',
    long_description=readme(),
    long_description_content_type='text/markdown',
    keywords='Bitcoin Improvement Proposal BIP39 Mnemonic Phrase Generator and Verifier Secure Coding Principles and '
             'Practices PA193 Faculty of Informatics FI Masaryk University MU MUNI FIMU FIMUNI ',
    url='https://github.com/mvondracek/PA193_mnemonic_Slytherin',
    author=__author__,

    python_requires='>=3.5, <4',
    packages=['BIP39 Mnemonic Phrase Generator and Verifier'],
    install_requires=[
        'coloredlogs',
    ],
    tests_require=[
        'nose',
    ],
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
            'mnemoniccli = PA193_mnemonic_Slytherin.mnemoniccli:cli_entry_point',
        ]
    },
    include_package_data=True,
    zip_safe=False,

    project_urls={
        'Bug Reports': 'https://github.com/mvondracek/PA193_mnemonic_Slytherin/issues',
        'Source': 'https://github.com/mvondracek/PA193_mnemonic_Slytherin',
        'Secure Coding Principles and Practices (PA193)': 'https://is.muni.cz/course/fi/autumn2019/PA193?lang=en',
        'Faculty of Informatics (FI)': 'https://www.fi.muni.cz/index.html.en',
        'Masaryk University (MU)': 'https://www.muni.cz/en',
    },
)
