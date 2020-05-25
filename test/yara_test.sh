#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "[*] Usage: $0  <myrule.yara>"
	exit
fi

if [[ ! -f $(which yara) ]]; then
	echo "[-] Could not locate yara on the system !"
	echo "[-] Reinstall yara globally and try"
	exit
fi

if [[ ! -f $(which sgn) ]]; then
	echo "[-] Could not locate sgn on the system !"
	echo "[-] Rebuild SGN or set the correct GOPATH for global access"
	exit
fi


if [[ ! -f $1 ]]; then
	echo "[-] Could not open YARA rule file: $1"
	exit
fi


RULE_FILE=$1

test_rule() {
	for i in {1..200}
	do
		generate_random
		sgn $PLAIN_DECODER -a $ARCHITECTURE -c $ENCODING_COUNT -max $OBFUSCATION_LEVEL data &> /dev/null
		if [[ `yara -c $RULE_FILE data.sgn` == 0 ]]; then
			print_fail
		fi
		rm data data.sgn &> /dev/null
	done
}


print_fail() {
	echo -e "\n[!] Found one sample that does not match !"
	echo "[*] Used parameters : sgn $PLAIN_DECODER -a $ARCHITECTURE -c $ENCODING_COUNT -max $OBFUSCATION_LEVEL data"
	echo -e "[*] Used test data: \n`xxd data`"
	echo -e "\n[!] RULE FAILED :("
	exit
}

print_stage() {
	echo "[STAGE $STAGE]> $INTERVAL_MIN-$INTERVAL_MAX byte | Architecture: $ARCHITECTURE | Encode Count: $ENCODING_COUNT | Obfuscation Level: $OBFUSCATION_LEVEL bytes |  Plain Stub: $PLAIN_DECODER"	
}

generate_random() {
	head -c $(($INTERVAL_MIN + RANDOM % $INTERVAL_MAX)) /dev/urandom > data
}


reset_stage(){
	INTERVAL_MIN=100
	INTERVAL_MAX=500
	ENCODING_COUNT=1
	OBFUSCATION_LEVEL=50	
	ARCHITECTURE=32
}

next_stage() {
	STAGE=$((STAGE+1))
	ITERATION=1O0
	INTERVAL_MIN=$((INTERVAL_MIN*2))
	INTERVAL_MAX=$((INTERVAL_MAX*2))
	if [[ $((STAGE%6)) > 4 ]]; then
		ENCODING_COUNT=$((ENCODING_COUNT+1))	
	fi
	OBFUSCATION_LEVEL=$((OBFUSCATION_LEVEL+10))
}

# Set the first stage test parameters
STAGE=1
PLAIN_DECODER="-plain-decoder"
INTERVAL_MIN=100
INTERVAL_MAX=500
ARCHITECTURE=32
ENCODING_COUNT=1
OBFUSCATION_LEVEL=50



## Start testing...
echo -e "\n[### STARTING PLAIN DECODER TESTS ###]"
echo -e "[!] Each stage could take 10-20 seconds.\n"


for j in {1..2}
do
	# x86 tests...
	for i in {1..6}
	do
		print_stage
		test_rule
		next_stage
	done

	reset_stage

	# x64 tests...
	ARCHITECTURE=64
	for i in {1..6}
	do
		print_stage
		test_rule
		next_stage
	done

	reset_stage

	if [[ $j == 1 ]]; then
		# Turn off plain decoder
		echo -e "\n[### STARTING OBFUSCATED DECODER TESTS ###]\n"
		PLAIN_DECODER=""	
	fi

done


echo -e "\n[+] $1 SUCCESS !!"
echo "[+] It seems that your rule passed all required tests. Now you should check out the false positive ratio of your rule."
echo "[+] If you think it is acceptable open a issue with your yara rule on the repo https://github.com/EgeBalci/sgn/issues/new"

# EICAR
