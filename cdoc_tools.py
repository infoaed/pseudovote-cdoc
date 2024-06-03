#!/usr/bin/python3

# apt-get install python3-m2crypto python3-pyasn1 python3-pycryptodome

import sys, os, math, hashlib, codecs
from M2Crypto import X509, EC
from pyasn1.codec.der import decoder
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

def ib(i, l=0):
    s = b""
    while i or l > 0:
        s = bytes([0xff & i]) + s
        i >>= 8
        l-=1
    return s

def concatKDF_SHA384(z, outlen, otherinfo):
    reps = int(math.ceil(outlen/32.0))
    output = b""
    for i in range(1,reps+1):
        output+= hashlib.sha384(ib(i,4)+z+otherinfo).digest()
    return output[:outlen]

def aes_wrap(kek, plain):
    encrypt = AES.new(kek, AES.MODE_ECB).encrypt

    n = len(plain)//8
    R = [None] + [plain[i*8:i*8+8] for i in range(0, n)]
    A = codecs.decode("A6A6A6A6A6A6A6A6", 'hex')

    for j in range(0, 6):
        for i in range(1, n+1):
            plaintext = A + R[i]
            B = encrypt(plaintext)
            A = strxor(B[:8], ib(n*j+i,8))
            R[i] = B[8:]

    R[0] = A
    return b"".join(R)

def aes_gcm_encrypt(key, plaintext, iv):
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext)
    encryptor.finalize()
    return (ciphertext, encryptor.tag)

def encrypt_cdoc(filename, content, certs, outfile = None):
    
    #print(f"Creating {outfile} for {len(certs)} certs...")

    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <denc:EncryptedData xmlns:denc="http://www.w3.org/2001/04/xmlenc#" MimeType="application/octet-stream">
        <denc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">%keyinfos%
        </ds:KeyInfo>
        <denc:CipherData>
            <denc:CipherValue>%ciphervalue%
            </denc:CipherValue>
        </denc:CipherData>
        <denc:EncryptionProperties>
            <denc:EncryptionProperty Name="LibraryVersion">qdigidocclient|3.13.2.1498</denc:EncryptionProperty>
            <denc:EncryptionProperty Name="Filename">%filename%</denc:EncryptionProperty>
            <denc:EncryptionProperty Name="DocumentFormat">ENCDOC-XML|1.1</denc:EncryptionProperty>
            <denc:EncryptionProperty Name="orig_file">%filename%|%filesize%|application/octet-stream|D0</denc:EncryptionProperty>
        </denc:EncryptionProperties>
    </denc:EncryptedData>
    """
    #content = bytes(data, "utf-8")
    xml = xml.replace('%filename%', os.path.basename(filename))
    xml = xml.replace('%filesize%', str(len(content)))

    # AES encrypt the data
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    ciphertext, tag = aes_gcm_encrypt(aes_key, content, iv)
    ciphertext = iv + ciphertext + tag
    xml = xml.replace('%ciphervalue%', codecs.encode(ciphertext, 'base64').strip().decode())

    xml_encryptedkey_RSA = """
            <denc:EncryptedKey Recipient="%recipient%">
                <denc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>%x509certificate%
                        </ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
                <denc:CipherData>
                    <denc:CipherValue>%ciphervalue%
                    </denc:CipherValue>
                </denc:CipherData>
            </denc:EncryptedKey>"""

    xml_encryptedkey_ECC = """
            <denc:EncryptedKey Recipient="%recipient%">
                <denc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/>
                <ds:KeyInfo>
                    <denc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
                        <denc11:KeyDerivationMethod xmlns:denc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
                            <denc11:ConcatKDFParams AlgorithmID="00%AlgorithmID%" PartyUInfo="00%PartyUInfo%" PartyVInfo="00%PartyVInfo%"> 
                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha384"/>
                            </denc11:ConcatKDFParams>
                        </denc11:KeyDerivationMethod>
                        <denc:OriginatorKeyInfo>
                            <ds:KeyValue>
                                <dsig11:ECKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
                                    <dsig11:NamedCurve URI="urn:oid:%curve_oid%"/>
                                    <dsig11:PublicKey>%ephemeral_pubkey%
                                    </dsig11:PublicKey>
                                </dsig11:ECKeyValue>
                            </ds:KeyValue>
                        </denc:OriginatorKeyInfo>
                        <denc:RecipientKeyInfo>
                            <ds:X509Data>
                                <ds:X509Certificate>%x509certificate%
                                </ds:X509Certificate>
                            </ds:X509Data>
                        </denc:RecipientKeyInfo>
                    </denc:AgreementMethod>
                </ds:KeyInfo>
                <denc:CipherData>
                    <denc:CipherValue>%ciphervalue%
                    </denc:CipherValue>
                </denc:CipherData>
            </denc:EncryptedKey>"""

    keyinfos = ""
    
    for cert_string in certs: # add EncryptedKey element for every recipient
        cert = X509.load_cert_der_string(cert_string)
        subject = cert.get_subject()

        #    print(subject)
        #    if subject.OU != "authentication":
        #        print("[-] Only authentication certificates are supported (%s): %s" % (certfile, subject.OU))
        #        sys.exit(1)

        recipient = subject.CN
        if "\x00" in subject.CN:
            recipient = subject.CN.decode('utf_16_be').encode('utf8')

        #    if subject.O == "ESTEID":
        #        recipient+=",ID-KAART"
        #    elif subject.O == "ESTEID (DIGI-ID)":
        #        recipient+=",DIGI-ID"
        #    else:
        #        print("[-] Unknown type of certificate (%s): %s" % (certfile, subject.O))
        #        sys.exit(1)

        # encrypt AES transport key
        pub_key = cert.get_pubkey()

        # ECC case
        EC_pubkey = EC.pub_key_from_der(pub_key.as_der())
        EC_keypair = EC.gen_params(EC.NID_secp384r1)
        EC_keypair.gen_key()
        shared_secret = EC_keypair.compute_dh_key(EC_pubkey)

        # format public key
        der = EC_keypair.pub().get_der()
        curve_oid = str(decoder.decode(bytes(der))[0][0][1])
        pubkey_bits = list(decoder.decode(bytes(der))[0][1])
        pubkey = ib((int(''.join(map(str, pubkey_bits)), 2)))

        # derive wrap key (KEK) from shared secret
        wrap_key = concatKDF_SHA384(shared_secret, 32, b"ENCDOC-XML|1.1"+pubkey+cert.as_der())
        ciphertext = aes_wrap(wrap_key, aes_key)

        keyinfos += xml_encryptedkey_ECC\
            .replace('%recipient%', recipient)\
            .replace('%AlgorithmID%', codecs.encode(b"ENCDOC-XML|1.1", 'hex').decode().upper())\
            .replace('%PartyUInfo%', codecs.encode(pubkey, 'hex').decode().upper())\
            .replace('%PartyVInfo%', codecs.encode(cert.as_der(), 'hex').decode().upper())\
            .replace('%curve_oid%', curve_oid)\
            .replace('%ephemeral_pubkey%', codecs.encode(pubkey, 'base64').strip().decode())\
            .replace('%x509certificate%', codecs.encode(cert.as_der(), 'base64').strip().decode())\
            .replace('%ciphervalue%', codecs.encode(ciphertext, 'base64').strip().decode())


    xml = xml.replace('%keyinfos%', keyinfos)
    
    if outfile:
        open(outfile, 'wb').write(xml.encode())
    else:
        return xml.encode()