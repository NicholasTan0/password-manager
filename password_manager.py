#!pip install pycryptodome

import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64decode
import json
from base64 import b64encode
import os.path
import hashlib
import random
import string
import sys

#PasswordVault is a List of String
# Each string in a password value is of the form: ``username:password:domain''

def encryptFile(plaintextData,key):
    cipher = AES.new(key, AES.MODE_GCM)
    header = b"header"
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintextData)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    encryptionResults = json.dumps(dict(zip(json_k, json_v)))
    return encryptionResults


def decryptFile(encryptedJson,key):
    b64_data = json.loads(encryptedJson)
    nonce = b64decode(b64_data['nonce'])
    header = b64decode(b64_data['header'])
    ciphertext = b64decode(b64_data['ciphertext'])
    tag = b64decode(b64_data['tag'])
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(header)
    decryptionResults = cipher.decrypt_and_verify(ciphertext, tag)
    return decryptionResults


def computerMasterKey(password):
    password = password.encode('utf-8')
    salt = b"<\n<~\x0e\xeetGR\xfe;\xec \xfc)8"
    key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
    return key


def decryptAndReconstructVault(hashedusername, password):
    key = computerMasterKey(password)
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'

    with open(hashedusername, "r") as file:
        fileread = file.read()
    file.close()
    decryptedresults = decryptFile(fileread,key)
    decodedContent = decryptedresults.decode('utf-8')
    if(decodedContent.startswith(magicString)):
        decodedContent = decodedContent[len(magicString):]
    else:
        raise Exception("Invalid password vault")
    passwordvault = []
    for line in decodedContent.splitlines():
        passwordvault.append(line)
    return passwordvault


def checkVaultExistenceOrCreate():
    passwordvault = []
    while True:
        username = input('enter vault username: ')
        password = input('enter vault password: ')

        if username and password:
            break

    hashedusername = hashlib.sha256(username.encode("utf-8")).hexdigest()
    if (os.path.exists(hashedusername)):
        passwordvault = decryptAndReconstructVault(hashedusername,password)

    else:
        print("Password vault not found, creating a new one")
        pass

    return username, password, hashedusername, passwordvault

def generatePassword():
    characters = string.ascii_letters + string.digits
    result = ''.join(random.choice(characters) for i in range(16))
    return result


def AddPassword(passwordvault):
    while True:
        username = input('enter username: ')
        password = input('enter password: ')
        domain = input('enter domain: ')

        if username and password and domain:
            break

    for entry in passwordvault:
        entry_username, entry_password, entry_domain = entry.split(':')
        if entry_domain == domain:
            print('Domain already exists')
            return

    passwordvault.append(username + ':' + password + ':' + domain)
    print('Record Entry added')

def CreatePassword(passwordvault):
    while True:
        username = input('enter username: ')
        domain = input('enter domain: ')

        if username and domain:
            break

    for entry in passwordvault:
        entry_username, entry_password, entry_domain = entry.split(':')
        if entry_domain == domain:
            print('Domain already exists')
            return

    password = generatePassword()
    passwordvault.append(username + ':' + password + ':' + domain)
    print('Record Entry added')

def UpdatePassword(passwordvault):
    while True:
        domain = input('enter domain: ')
        if domain:
            break

    for i in range(len(passwordvault)):
        username, password, old_domain = passwordvault[i].split(':')

        if old_domain == domain:
            new_password = generatePassword()

            passwordvault[i] = username + ':' + new_password + ':' + domain
            print('Record Entry Updated')
            return
    print('Domain not found')

def LookupPassword(passwordvault):
    while True:
        domain = input('enter domain: ')
        if domain:
            break

    for entry in passwordvault:
        username, password, entry_domain = entry.split(':')
        if entry_domain == domain:
            print('Password: ' + password)

def DeletePassword(passwordvault):
    while True:
        domain = input('enter domain: ')
        if domain:
            break

    for i in range(len(passwordvault)):
        username, password, entry_domain = passwordvault[i].split(':')

        if entry_domain == domain:
            del passwordvault[i]
            print('Record Entry Deleted')
            return
    print("Domain not found")

def displayVault(passwordvault):
    print(passwordvault)

def EncryptVaultAndSave(passwordvault, password, hashedusername):
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'
    key = computerMasterKey(password)
    finalString = ''
    finalString = finalString + magicString

    for i in passwordvault:
        record = i + '\n'
        finalString = finalString + record

    finaldbBytes = bytes(finalString, 'utf-8')
    finaldbBytesEncrypted = encryptFile(finaldbBytes,key)

    with open(hashedusername, "w") as file:
        file.write(finaldbBytesEncrypted)
    file.close()
    print("Password Vault encrypted and saved to file")


def main():
    username, password, hashedusername, passwordvault = checkVaultExistenceOrCreate()
    while(True):

        print('Password Management')
        print('-----------------------')
        print('-----------------------')
        print('1 - Add password')
        print('2 - Create password')
        print('3 - Update password')
        print('4 - Lookup password')
        print('5 - Delete password')
        print('6 - Display Vault')
        print('7 - Save Vault and Quit')
        choice = input('')

        if choice == ('1'):
            AddPassword(passwordvault)

        elif choice == ('2'):
            CreatePassword(passwordvault)

        elif choice == ('3'):
            UpdatePassword(passwordvault)

        elif choice == ('4'):
            LookupPassword(passwordvault)

        elif choice == ('5'):
            DeletePassword(passwordvault)
        elif choice == ('6'):
            displayVault(passwordvault)

        elif choice == ('7'):
            EncryptVaultAndSave(passwordvault, password, hashedusername)
            quit()
        else:
            print('Invalid choice please try again')


if __name__ == "__main__":
    main()