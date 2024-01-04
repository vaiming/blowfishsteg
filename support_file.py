"""

Dependencies :

Crypto -> pip install pycrypto


"""


import math
import sys

from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack

from ast import literal_eval
import wave

from humanfriendly import format_timespan
from time import time

""" Import Keperluan Hash File """
import hashlib
import wave

import subprocess
import shlex

def _os_execute(command):
    result, err = subprocess.Popen(
        shlex.split(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate()
    return result, err


""" === Generate MD5 Hash === """

def hash_file(folder, etc, filename, save_filename="", save_digest=False):
    md5_hash = hashlib.md5()

    current_file = open(folder + "/" + filename, "rb")
    buffer_file = current_file.read()
    md5_hash.update(buffer_file)
    print("filename hash_file : ", filename)

    digest = md5_hash.hexdigest()

    # create .txt file for
    result_filename = save_filename + etc + ".txt"
    if save_digest:
        f = open(folder + "/" + result_filename, 'w')
        f.write(digest)
        f.close()

    return digest




""" === KEPERLUAN HELPERS RC6 === """

#rotate right input x, by n bits
def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

#rotate left input x, by n bits
def ROL(x, n, bits = 32):
    return ROR(x, bits - n,bits)

#convert input sentence into blocks of binary
#creates 4 blocks of binary each of 32 bits.
def blockConverter(sentence):
    encoded = []
    res = ""
    for i in range(0,len(sentence)):
        if i%4==0 and i!=0 :
            encoded.append(res)
            res = ""
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) <8:
            temp = "0"*(8-len(temp)) + temp
        res = res + temp
    encoded.append(res)
    return encoded

#converts 4 blocks array of long int into string
def deBlocker(blocks):
    s = ""
    for ele in blocks:
        temp =bin(ele)[2:]
        if len(temp) <32:
            temp = "0"*(32-len(temp)) + temp
        for i in range(0,4):
            s=s+chr(int(temp[i*8:(i+1)*8],2))
    return s

#generate key s[0... 2r+3] from given input string userkey
def generateKey(userkey):
    r=12
    w=32
    b=len(userkey)
    modulo = 2**32
    s=(2*r+4)*[0]
    s[0]=0xB7E15163
    for i in range(1,2*r+4):
        s[i]=(s[i-1]+0x9E3779B9)%(2**w)
    encoded = blockConverter(userkey)
    #print encoded
    enlength = len(encoded)
    l = enlength*[0]
    for i in range(1,enlength+1):
        l[enlength-i]=int(encoded[i-1],2)
    
    v = 3*max(enlength,2*r+4)
    A=B=i=j=0
    
    for index in range(0,v):
        A = s[i] = ROL((s[i] + A + B)%modulo,3,32)
        B = l[j] = ROL((l[j] + A + B)%modulo,(A+B)%32,32) 
        i = (i + 1) % (2*r + 4)
        j = (j + 1) % enlength
    return s


""" === ENCRYPT RC6 """

#start_time = time()
def encrypt_rc6(sentence,s):
    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    B = (B + s[0])%modulo
    D = (D + s[1])%modulo 
    for i in range(1,r+1):
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + s[2*i])%modulo 
        C = (ROL(C^u,tmod,32) + s[2*i+ 1])%modulo
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + s[2*r + 2])%modulo 
    C = (C + s[2*r + 3])%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return orgi,cipher

def split_string(normal_text, n, symbol):
    pos = 0
    x = []
    res = ""
    for c in normal_text:
        if(pos%n==0):
            if(pos==0):
                res+=c
            else:
                x.append(res)
                res = "" 
                res+=c
        else:
            res+=c
        pos=pos+1
    carry = res
    i = 0
    msg_len = 16-len(carry)
    while i < msg_len:
        carry += symbol
        i = i + 1
    x.append(carry)
    return x

def proses_rc6_encrypt(filename, key, folder, etc):
    s = generateKey(key)
    rc6_result = []
    # add data yang akan di enkripsi
    start_time = time()
    f = open(filename, 'r', encoding='utf-8')

    list_text_rc6 = split_string(f.readline(), 16, "_")
    for res in list_text_rc6:
        print("split text ("+str(len(res))+") : "+res) 
        orgi, cipher = encrypt_rc6(res, s)
        esentence = deBlocker(cipher)
        rc6_result.append(esentence)
        print("Encrypted string ("+str(len(esentence))+") : ", esentence)
    rc6_result = "".join(rc6_result)
    print("join splited rc6 ("+str(len(rc6_result))+")"+rc6_result)

    # exper
    hexcipher = rc6_result.encode("utf-8").hex()
    print("rc6 1 "+str(len(rc6_result)))
    print("rc6 2 "+str(len(hexcipher)))
    print("rc6 3 "+str(len(bytes.fromhex(hexcipher).decode('utf-8'))))

    end_time = time()
    time_taken = end_time - start_time
    hours, rest = divmod(time_taken,3600)
    minutes, seconds = divmod(rest, 60)
    print("Time taken:",  format_timespan(end_time - start_time))    
    # # create file hasil enkripsi RC6
    result_filename = "ciphertextRC6" + etc + ".txt"

    f = open(folder + "/" + result_filename, 'w', encoding='utf-8')
    f.write(rc6_result.encode("utf-8").hex())
    f.close()

    return result_filename


""" === DECRYPT RC6 """ 


def decrypt_rc6(esentence, s):
    encoded = blockConverter(esentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    C = (C - s[2*r+3])%modulo
    A = (A - s[2*r+2])%modulo
    for j in range(1,r+1):
        i = r+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-s[2*i+1])%modulo,tmod,32)  ^u)  
        A = (ROR((A-s[2*i])%modulo,umod,32)   ^t) 
    D = (D - s[1])%modulo 
    B = (B - s[0])%modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    return cipher,orgi


def proses_rc6_decrypt(key, filename, add_digit, folder, etc):
    s = generateKey(key)

    print("nilai filename : ", filename)
    start_time = time()
    # add data yang akan di dekripsi
    f = open(folder + "/" + filename, "r", encoding='utf-8')
    plaintext = bytes.fromhex(f.readline()).decode('utf-8')
    list_text_rc6 = split_string(plaintext, 16, "_")
    decrypted_result = []
    for res in list_text_rc6:
        cipher, orgi = decrypt_rc6(res, s)
        sentence = deBlocker(orgi)

        print("nilai sentence : ", sentence)
        decrypted_result.append(sentence)

        # create file hasil dekripsi
    end_time = time()
    time_taken = end_time - start_time
    hours, rest = divmod(time_taken,3600)
    minutes, seconds = divmod(rest, 60)
    print("Time taken:",  format_timespan(end_time - start_time))
    decrypted_result = "".join(decrypted_result)
    result_filename = folder + "/textRC6" + etc + ".txt"
    f = open(result_filename, "w", encoding='utf-8')
    f.write(decrypted_result.replace("_","") )
    f.close()

    return result_filename


""" === ENCRYPT BLOWFISH === """


def encrypt_blowfish(key, filename, folder, etc):
    bs = Blowfish.block_size
    iv = Random.new().read(bs)

    start_time = time()
    print("\n\nnilai iv - encrypt : ", iv)
    print("len iv : ", len(iv))
    key = literal_eval("b'{}'".format(key))
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # read file ciphertextRC6
    f = open(folder + "/" + filename, "r", encoding='utf-8')
    plaintext = f.readline()
    print("plntxt 1 "+ plaintext.encode("utf-8").hex())

    add_digit = 0
    if len(plaintext.encode()) % 8 != 0:
        add_digit = 8 - len(plaintext.encode()) % 8
        plaintext = plaintext + " " * (8 - len(plaintext.encode()) % 8)

    encrypt_msg = iv + cipher.encrypt(plaintext)
    print("plntxt 2 "+str(len(plaintext)))

    print("encrypt : "+str(len(cipher.encrypt(plaintext))))
    print("iv : "+str(len(iv)))
    print("encrypt_msg : "+str(len(encrypt_msg)))

    end_time = time()
    time_taken = end_time - start_time
    hours, rest = divmod(time_taken,3600)
    minutes, seconds = divmod(rest, 60)
    print("Time taken:",  format_timespan(end_time - start_time))
    # create file ciphertext Blowfish
    result_filename = "ciphertextBlowfish" + etc + ".txt"
    f = open(folder + "/" + result_filename, "w", encoding='utf-8')
    f.write(str(encrypt_msg)[2:-1])
    f.close()

    return result_filename, add_digit

    # bs = Blowfish.block_size
    # iv = Random.new().read(bs)
    # blowfish_result = []
    # print("\n\nnilai iv - encrypt : ", iv)
    # print("len iv : ", len(iv))
    # key = literal_eval("b'{}'".format(key))
    # cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # # # read file ciphertextRC6
    # f = open(folder + "/" + filename, "r", encoding='utf-8')
    # list_text_blowfish = split_string(f.readline(), 8, "_")
    # for res in list_text_blowfish:
    #     print("split text ("+str(len(res))+") :" +res )
    #     add_digit = 0
    #     if len(res.encode()) % 8 != 0:
    #         add_digit = 8 - len(res.encode()) % 8
    #         res = res + " " * (8 - len(res.encode()) % 8)
    #     encrypt_msg = iv + cipher.encrypt(res)
    #     blowfish_result.append(encrypt_msg)
    #     # cuma buat liat tipe variabel
    #     print(type(encrypt_msg))
    #     # cuma buat liat tipe variabel
    #     encrypt_msg.hex()
    #     print(len(encrypt_msg.hex()))
    # blowfish_result = "".join(blowfish_result)
    # print(blowfish_result)





    # add_digit = 0
    # if len(plaintext.encode()) % 8 != 0:
    #     add_digit = 8 - len(plaintext.encode()) % 8
    #     plaintext = plaintext + " " * (8 - len(plaintext.encode()) % 8)

    # encrypt_msg = iv + cipher.encrypt(plaintext)

    # # create file ciphertext Blowfish
    # result_filename = "ciphertextBlowfish" + etc + ".txt"
    # f = open(folder + "/" + result_filename, "w", encoding='utf-8')
    # f.write(str(encrypt_msg)[2:-1])
    # f.close()

    # return result_filename, add_digit


""" === DECRYPT BLOWFISH === """

def decrypt_blowfish(key, filename, folder, etc):
    bs = Blowfish.block_size
    
    start_time = time()
    #key = literal_eval("b'{}'".format(key))
    print("nilai key : ", key)
    # read file hasil ekstraksi dari file audio
    f = open(folder + "/" + filename, "r", encoding='utf-8')
    encrypt_msg = f.read()

    print("\n\nnilai encrypt_msg : ", encrypt_msg)

    # convert to propery bytes format
    encrypt_msg = literal_eval("b'{}'".format(encrypt_msg))

    iv = encrypt_msg[:bs]
    decrypt_msg = encrypt_msg[bs:]

    print("\n\nnilai iv : ", iv)
    print("\n\nniai decrypt_msg : ", decrypt_msg)
    print("\n\nnilai type(decrypt_msg) : ", type(decrypt_msg))

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    msg = cipher.decrypt(decrypt_msg)
    print("\n\nhasil decrypt Blowfish : ", type(msg))
    print("\n\nhasil decrypt : ", msg)

    end_time = time()
    time_taken = end_time - start_time
    hours, rest = divmod(time_taken,3600)
    minutes, seconds = divmod(rest, 60)
    print("Time taken:",  format_timespan(end_time - start_time))
    result_filename = folder + "/textBlowfish" + etc + ".txt"
    f = open(result_filename, "w", encoding='utf-8')
    f.write(str(msg.decode()))
    f.close()

    return result_filename


""" === INPUT TEXT TO AUDIO === """


def input_text_audio(filename_text, filename_audio, etc, folder):
    # read file audio yang akan disisipi text
    song = wave.open(filename_audio, mode="rb")
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    start_time = time()
    # read file text yang akan disisipkan
    f = open(folder + "/" + filename_text, "r", encoding='utf-8')
    string = f.readline()
    string = string + int((len(frame_bytes) - (len(string)*8*8)) / 8) * '#'

    bits = list(map(int, ''.join([bin(ord(i)).lstrip('0b').rjust(8,'0') for i in string])))

    for i, bit in enumerate(bits):
        frame_bytes[i] = (frame_bytes[i] & 254) | bit

    frame_modified = bytes(frame_bytes)

    end_time = time()
    time_taken = end_time - start_time
    hours, rest = divmod(time_taken,3600)
    minutes, seconds = divmod(rest, 60)
    print("Time taken:",  format_timespan(end_time - start_time))
    # create file audio
    result_filename = filename_audio.split(".")[0] + "_result" + etc + ".wav"
    with wave.open(folder + "/" + result_filename, "wb") as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_modified)
    song.close()

    return result_filename


""" === OUTPUT TEXT FROM AUDIO === """

def output_text_audio(filename_audio, folder, etc):
    # read file audio
    song = wave.open(folder + "/" + filename_audio, mode="rb")

    start_time = time()
    # convert audio to byte array
    frame_bytes = bytearray(list(song.readframes(song.getnframes())))

    # Extract the LSB of each byte
    extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]

    # convert byte array back to string
    string = "".join(chr(int("".join(map(str,extracted[i: i+8 ])), 2)) for i in range(0, len(extracted), 8))
    # cut off at the filler characters
    decode = string.split("###")[0]

    end_time = time()
    time_taken = end_time - start_time
    hours, rest = divmod(time_taken,3600)
    minutes, seconds = divmod(rest, 60)
    print("Time taken:",  format_timespan(end_time - start_time))
    # create text result
    result_filename = folder + "/textExtraction" + etc + ".txt"
    f = open(result_filename, "w", encoding='utf-8')
    f.write(decode)
    f.close()

    song.close()

    return "textExtraction.txt"