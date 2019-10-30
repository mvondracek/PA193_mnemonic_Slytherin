from PA193_mnemonic_Slytherin.mnemonic import Entropy, Mnemonic, Seed, _DictionaryAccess, ENGLISH_DICTIONARY_PATH
from PA193_mnemonic_Slytherin.mnemonic import generate, recover, verify

from mnemonic import Mnemonic as reference_Mnemonic

ref_Mnemonic = reference_Mnemonic("english")

while True:
    password = ""
    test_mnemonic = ref_Mnemonic.generate()
    test_entropy =  bytes(ref_Mnemonic.to_entropy(test_mnemonic))
    test_seed = bytes(ref_Mnemonic.to_seed(test_mnemonic, password))
    test_mnemonic2 = ref_Mnemonic.to_mnemonic(test_entropy)
    
    if test_entropy != Mnemonic(test_mnemonic).to_entropy():
        print("difference for conversion to entropy for '{}'".format(test_mnemonic))
    if test_seed != bytes(Mnemonic(test_mnemonic).to_seed(password)): # cant use secure seed compare here hence the conversion to bytes
        print("difference for conversion to seed for '{}' and '{}'".format(test_mnemonic, password))
    if test_mnemonic2 != Entropy(test_entropy).to_mnemonic():
        print("difference for conversion to mnemonic for '{}'".format(test_mnemonic))
