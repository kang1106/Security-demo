This demo is TLS connection based on PSK, Cipher is TLS_AES_128_GCM_SHA256
openssl test demo:
openssl s_server -port 4433  -nocert -psk 1a2b3c4d5e -debug -ciphersuites TLS_AES_128_GCM_SHA256
openssl s_client -connect 127.0.0.1:4433 -psk 1a2b3c4d5e -psk_identity psk_ecub -debug

Change to Server folder, run ./Server
Change to Client folder, run ./Client 127.0.0.1 4433
