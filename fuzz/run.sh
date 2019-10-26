fails=0
echo "" > fails
while true
 do
   radamsa test_mnemonic_str > mnemonic_str
   radamsa test_entropy_bin > entropy_bin
   radamsa test_entropy_hex > entropy_hex
   radamsa test_seed_bin > seed_bin
   radamsa test_seed_hex > seed_hex

   mnemoniccli -g -e entropy_hex -s seed -m mnemonic &>out
   if [[ "$?" != "0" && "$?" != "65" ]] ; then mkdir "$fails" ; cat out >> fails ; cp entropy_hex "$fails" ; mv out "$fails" ; let "fails++" ; fi
   mnemoniccli -g -e entropy_bin -s seed -m mnemonic -f bin &>out
   if [[ "$?" != "0" && "$?" != "65" ]] ; then mkdir "$fails" ; cat out >> fails ; cp entropy_bin "$fails" ; mv out "$fails" ; let "fails++" ; fi
   mnemoniccli -r -m mnemonic_str -s seed -e entropy &>out
   if [[ "$?" != "0" && "$?" != "65" ]] ; then mkdir "$fails" ; cat out >> fails ; cp mnemonic_str "$fails" ; mv out "$fails" ; let "fails++" ; fi
   mnemoniccli -v -m mnemonic_str -s seed_hex &>out
   if [[ "$?" != "0" && "$?" != "65" ]] ; then mkdir "$fails" ; cat out >> fails ; cp mnemonic_str "$fails" ; cp seed_hex "$fails" ; mv out "$fails" ; let "fails++" ; fi
   mnemoniccli -v -m mnemonic_str -s seed_bin -f bin &>out
   if [[ "$?" != "0" && "$?" != "65" ]] ; then mkdir "$fails" ; cat out >> fails ; cp mnemonic_str "$fails" ; cp seed_bin "$fails" ; mv out "$fails" ; let "fails++" ; fi
 done

