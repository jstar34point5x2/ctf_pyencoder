
import codecs, base64, hashlib


# %% Rotate

def enc_rot13(string):
    r13 = codecs.encode(string, 'rot_13')
    return r13

# %% Base
    

def enc_base16(string):
    
    data_string = string.encode('utf-8')
    encoded = base64.b16encode(data_string)
    encoded = encoded.decode("utf-8")
    return encoded

def enc_base32(string):

    data_string = string.encode('utf-8')
    encoded = base64.b32encode(data_string)
    encoded = encoded.decode("utf-8")
    return encoded

def enc_base64(string):
    
    data_string = string.encode('utf-8')
    encoded = base64.b64encode(data_string)
    encoded = encoded.decode("utf-8")
    return encoded
    

def enc_base85(string):
    
    data_string = string.encode('utf-8')
    encoded = base64.b85encode(data_string)
    encoded = encoded.decode("utf-8")
    return encoded

# %% Numerical
    

def enc_md5(string):
    
    md5_sig = hashlib.md5(string.encode()).hexdigest()
    return md5_sig

def enc_sha1(string):
    
    sha1_sig = hashlib.sha1(string.encode()).hexdigest()
    return sha1_sig
    
def enc_sha256(string):
    sha256_signature = hashlib.sha256(string.encode()).hexdigest()
    return sha256_signature
    
def enc_binary(string):
    
    a_bytes = bytes(string, "ascii")
    binary = ' '.join(["{0:b}".format(x) for x in a_bytes])
    return binary
    
def enc_hex(string):
    bytees = string.encode('utf-8')
    hex_string = bytees.hex()
    hex_string = octets(hex_string)
    return hex_string

# %% Utilities
    
def octets(string):
    octstring = ''
    for i in range(1,len(string) + 1):
        if (i-1) % 4 == 0:
            octstring = octstring + ' '
        octstring = octstring + string[i-1]
    return octstring

def report_space(label, value):

    end_lab = 20
    pad = 2
    new_line = label.rjust(end_lab) + ' ' * pad + value.ljust(0)
    print('\n' + new_line)

def read_file(filepath):
    file = open(filepath,"r")
    txt_cont=file.read()
    file.close()
    return txt_cont

# %% Report (from user or file)

user = True

if user == True:
    string = input('\nEnter text here:'.rjust(20) + '  ')
else:
    filepath = input ('\nEnter file path'.rjust(20) + '  ')
    string = read_file(filepath)

report = True

if report == True:

    report_space('encoded rot13:', enc_rot13(string))
    report_space('encoded base16:', enc_base16(string))
    report_space('encoded base32:', enc_base32(string))
    report_space('encoded base64:', enc_base64(string))
    report_space('encoded base85:', enc_base85(string))
    report_space('encoded basemd5:', enc_md5(string))
    report_space('encoded sha1:', enc_sha1(string))
    report_space('encoded sha256:', enc_sha256(string))
    report_space('encoded binary:', enc_binary(string))
    report_space('encoded hex:', enc_hex(string))
    print()
