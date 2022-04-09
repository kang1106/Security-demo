#!/usr/bin/env python
import argparse
from OpenSSL import crypto
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

"""
# Function definations
"""
def X509_to_Public_Key(x509, public_key):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(x509).read())
    print('public key length: ', cert.get_pubkey().bits())

    print('public key:\n', crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))
    f = open(public_key, 'w')
    f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8"))

def HSM_Signing_Tool_Public_Key_Decimal(public_key):
    
    f = open(public_key,'r')
    key = RSA.importKey(f.read())

    print()
    print('The decimal equivalent of the public modulas is')
    print()
    print()
    
    for i in range(383,-1,-1):
        print((key.n>>(8*i))&(0xff),end=' ')

    print()
    print()
    print('The public exponent is')
    print()

    print((key.e>>(16))&(0xff),end=' ')
    print((key.e>>(8))&(0xff),end=' ')
    print((key.e)&(0xff),end=' ')
    print()
    print()


def HSM_Signing_Tool_Sign(input_binary,private_key):
    print()
    print('The PKCS 1.5 RSA3072 signature of the SHA256 hash of the binary is\n')

    message = open(input_binary,'rb').read()
    key = RSA.importKey(open(private_key,'r').read())
    h = SHA256.new()
    h.update(message)
    signature = PKCS1_v1_5.new(key).sign(h)

    print('{',end='')
    for i in range(0,384):
        if(383 == i):
            print(hex(signature[i]),end='')
        else:
            print(hex(signature[i]),end=', ')
    print('}')
    
    signature_file = open("output_binaries/signature.bin", "wb")
    signature_file.write(signature)
    
    signed_binary = open("output_binaries/signed_binary.bin", "wb")
    signed_binary.write(message)
    signed_binary.write(signature)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                                     description="This script generates\n"+
                                     "1. The PKCS1.5 RSA3072 SHA256 signature of the input image using the input key\n"+
                                     "2. Prints the decimal equivalent of the public modulas and public exponent of\n"+
                                     "   the input PEM RSA3072 public key. These output strings can used in the HSM\n"+
                                     "   public key configuration\n")
    
    parser.add_argument("-o", "--option", dest="option",
                        choices={'public_key_2_console', 'sign', 'cert'},
                        help="public_key_2_console : Print public modulas and exponent to console \
                              sign : sign the input binary with PKCS1.5 RSA3072 SHA256",
                        default="sign")
    parser.add_argument("-p", "--public_key", dest="public_key",
                        help="public_key path",
                        default="sample_key_pair\sample_key_pub.pem")
    parser.add_argument("-c", "--certificate", dest="certificate",
                        help="certificate path",
                        default="sample_key_pair\sample_key_pub.pem")
    parser.add_argument("-out", "--public_key_file", dest="public_key_file",
                        help="public key file path",
                        default="sample_key_pair\sample_key_pub.pem")
    parser.add_argument("-s", "--private_key", dest="private_key",
                        help="private_key path",
                        default="sample_key_pair/sample_key_pri.pem")
    parser.add_argument("-i", "--input_binary", dest="input_binary",
                        help="input_binary path",
                        default="sample_input_binary/sample_input_binary.bin")

    args, extra = parser.parse_known_args()
    
    if("public_key_2_console" == args.option):
        HSM_Signing_Tool_Public_Key_Decimal(args.public_key)
    elif("cert" == args.option):
        X509_to_Public_Key(args.certificate, args.public_key_file)
    else:
        HSM_Signing_Tool_Sign(args.input_binary,args.private_key)