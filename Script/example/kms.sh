#!/usr/bin/expect
spawn kms-tool sign-hash -f hash.tmp -a SHA2_256 -p PKCS_V1_5 -k 1648720 -o hash_sig.tmp
expect "Enter pin:"
send "123123\r"
interact
