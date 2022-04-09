#!/bin/bash
mv $1 GWM_IHU.tmp
dd if=GWM_IHU.tmp of=seg.tmp ibs=48 count=1
openssl dgst -sha256 -binary -out  hash.tmp seg.tmp
./kms.sh
cat hash_sig.tmp GWM_IHU.tmp > $1
rm *.tmp
