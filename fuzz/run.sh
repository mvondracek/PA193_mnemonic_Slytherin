#!/bin/bash

handle_fail()
{
  let "fails++"; mkdir "fail-${fails}" ; sed -i "1iFailed instance number ${fails}, with password '${password}'" out ; cat out ; cat out >> fails ; mv out "fail-${fails}" ;
}>&2

fails=0
runs=0
echo -n "" > fails
while true
 do
   password=""
   radamsa test_mnemonic_str > mnemonic_str
   radamsa test_entropy_bin > entropy_bin
   radamsa test_entropy_hex > entropy_hex
   radamsa test_seed_bin > seed_bin
   radamsa test_seed_hex > seed_hex

   mnemoniccli -g -e entropy_hex -s seed -m mnemonic -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 2 ]] ; then handle_fail ; cp entropy_hex "fail-${fails}" ; fi
   mnemoniccli -g -e entropy_bin -s seed -m mnemonic -f bin -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 2 ]] ; then handle_fail ; cp entropy_bin "fail-${fails}" ; fi
   mnemoniccli -r -m mnemonic_str -s seed -e entropy -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 2 ]] ; then handle_fail ; cp mnemonic_str "fail-${fails}" ; fi
   mnemoniccli -v -m mnemonic_str -s seed_hex -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 125 && $? != 2 ]] ; then handle_fail ; cp mnemonic_str "fail-${fails}" ; cp seed_hex "fail-${fails}" ; fi
   mnemoniccli -v -m mnemonic_str -s seed_bin -f bin -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 125 && $? != 2 ]] ; then handle_fail ; cp mnemonic_str "fail-${fails}" ; cp seed_bin "fail-${fails}" ; fi

   password=$(echo "password123" | radamsa)
   mnemoniccli -g -e entropy_hex -s seed -m mnemonic -p "$password" -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 2 ]] ; then handle_fail ; cp entropy_hex "fail-${fails}" ; fi
   mnemoniccli -g -e entropy_bin -s seed -m mnemonic -p "$password" -f bin -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 2 ]] ; then handle_fail ; cp entropy_bin "fail-${fails}" ; fi
   mnemoniccli -r -m mnemonic_str -s seed -e entropy -p "$password" -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 2 ]] ; then handle_fail ; cp mnemonic_str "fail-${fails}" ; fi
   mnemoniccli -v -m mnemonic_str -s seed_hex -p "$password" -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 125 && $? != 2 ]] ; then handle_fail ; cp mnemonic_str "fail-${fails}" ; cp seed_hex "fail-${fails}" ; fi
   mnemoniccli -v -m mnemonic_str -s seed_bin -p "$password" -f bin -ll debug &>out
   if [[ $? != 0 && $? != 65 && $? != 125 && $? != 2 ]] ; then handle_fail ; cp mnemonic_str "fail-${fails}" ; cp seed_bin "fail-${fails}" ; fi

   runs=$((runs + 10))
   echo "Fails: ${fails} / ${runs}"
done

