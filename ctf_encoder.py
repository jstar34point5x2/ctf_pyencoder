import codecs, base64, hashlib

#rot13, base64, sha256

class Encoding:

    def rot13(string):
        r13 = codecs.encode(string, 'rot_13')
        print(' rot13 encoding: ' + r13 + '\n')
    
    
    def base(string):
        data_string = string.encode('utf-8')
        
        encoded = base64.b16encode(data_string)
        print('base16 encoding: ' + encoded.decode("utf-8") )
        print()
        
        encoded = base64.b32encode(data_string)
        print('base32 encoding: ' + encoded.decode("utf-8") )
        print()
        
        encoded = base64.b64encode(data_string)
        print('base64 encoding: ' + encoded.decode("utf-8") )
        print()
        
        encoded = base64.b85encode(data_string)
        print('base85 encoding: ' + encoded.decode("utf-8") )
        print()
        
    def encrypt_string(hash_string):
        
        sha_signature = \
            hashlib.md5(hash_string.encode()).hexdigest()
        print('   md5 encoding: '+ sha_signature)
        print()
        
        sha_signature = \
            hashlib.sha1(hash_string.encode()).hexdigest()
        print('  sha1 encoding: ' + sha_signature)
        print()
        
        
        sha_signature = \
            hashlib.sha256(hash_string.encode()).hexdigest()
        print('sha256 encoding: ' + sha_signature)
        print()
        
    def numerical(string):
        
        a_bytes = bytes(string, "ascii")
        binary = ' '.join(["{0:b}".format(x) for x in a_bytes])
        print('binary encoding: ' + binary)
        
        bytees = string.encode('utf-8')
        print('\n   hex encoding: ' + bytees.hex())
        print()

        


this = input('Enter text here: ')
print('\n  original text: ' + this + '\n')
Encoding.rot13(this)
Encoding.base(this)
Encoding.encrypt_string(this)
Encoding.numerical(this)

