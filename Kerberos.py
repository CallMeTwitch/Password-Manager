# Imports
from base64 import b64encode, b64decode
from os import urandom, system
from json import load, dump
from getpass import getpass
from random import choices
from SCRYPT import SCRYPT
from SECRET import HASH
from time import sleep
from HMAC import HMAC
from HKDF import HKDF
from AES import AES

# Helper Functions
b64encode_ = lambda input:b64encode(input).decode('utf-8')

def error(err):
    print(err)
    sleep(5)
    exit()

# Load Data
salts = load(open('salts.json', 'r'))
dataBase = load(open('dataBase.json', 'r'))

# Define Pseudo-Random Function
prf = lambda key, message:HMAC(key = key, msg = message, digestmod = HASH)

# Define Generation of Protected Keys
generateProtectedKey = lambda:''.join(choices('1234567890-=!@#$%^&*()_+qwertyuiop[]\QWERTYUIOP{}|asdfghjkl;ASDFGHJKL:zxcvbnm,./ZXCVBNM<>?', k = choices([*range(20, 25)], k = 1)[0])).encode()

action = input('Actions: \n\tSign Up (1)\n\tLog In (2)\n').lower()

# Sign Up
if action in {'sign up', '1'}:
    UID = b64encode_(HASH(input('\nUser Identification: ').encode()).digest())
    masterPassword = HASH(getpass('Master Password: ').encode()).digest()

    if UID in salts:
        error('User Already Exists.')

    salts[UID] = b64encode_(urandom(128))

    masterKey = SCRYPT(password = masterPassword, salt = b64decode(UID), N = 1_024, r = 4, p = 1, dkLen = 32, prf = prf)
    masterHash = SCRYPT(password = masterKey, salt = masterPassword, N = 1, r = 4, p = 1, dkLen = 64, prf = prf)
    authKey = b64encode_(SCRYPT(password = masterHash, salt = b64decode(salts[UID]), N = 1_024, r = 4, p = 1, dkLen = 128, prf = prf))

    if authKey in dataBase:
        error('Collision Error.')

    stretchedMasterKey = HKDF(input_key_material = masterKey, prf = prf, length = 32)    
    dataBase[authKey] = {}

# Log In
elif action in {'log in', '2'}:
    UID = b64encode_(HASH(input('\nUser Identification: ').encode()).digest())
    masterPassword = HASH(getpass('Master Password: ').encode()).digest()

    if UID not in salts:
        error('User Identification or Password Incorrect.')

    masterKey = SCRYPT(password = masterPassword, salt = b64decode(UID), N = 1_024, r = 4, p = 1, dkLen = 32, prf = prf)
    masterHash = SCRYPT(password = masterKey, salt = masterPassword, N = 1, r = 4, p = 1, dkLen = 64, prf = prf)
    authKey = b64encode_(SCRYPT(password = masterHash, salt = b64decode(salts[UID]), N = 1_024, r = 4, p = 1, dkLen = 128, prf = prf))

    if authKey not in dataBase:
        error('User Identification or Password is Incorrect.')

    stretchedMasterKey = HKDF(input_key_material = masterKey, prf = prf, length = 32)    

else:
    error('Action Unavailable.')

while True:
    system('cls')

    action = input('\nActions: \n\tAdd Protected Key (1)\n\tGet Protected Key (2)\n\tDelete Account (3)\n\tLog Out (4)\n').lower()

    # Add New Password
    if action in {'add protected key', '1'}:
        service = b64encode_(HASH(input('\nService: ').encode()).digest())

        if service in dataBase[authKey]:
            error('Service Already Exists.')

        dataBase[authKey][service] = [b64encode_(urandom(16))]
        dataBase[authKey][service] += [b64encode_(AES(stretchedMasterKey).encrypt_cbc(generateProtectedKey(), b64decode(dataBase[authKey][service][0])))]

    # Get Password
    elif action in {'get protected key', '2'}:
        service = b64encode_(HASH(input('\nService: ').encode()).digest())

        if service not in dataBase[authKey]:
            error('Service Does Not Exist.')

        print(AES(stretchedMasterKey).decrypt_cbc(b64decode(dataBase[authKey][service][1]), b64decode(dataBase[authKey][service][0])).decode())
        getpass('\nPlease Press Enter to Continue')
    
    # Delete Account
    elif action in {'delete account', '3'}:
        print('Please Sign in Again to Confirm Action.')

        UID = b64encode_(HASH(input('\nUser Identification: ').encode()).digest())
        masterPassword = HASH(getpass('Master Password: ').encode()).digest()

        if UID not in salts:
            error('User Identification or Password is Incorrect.')

        masterKey = SCRYPT(password = masterPassword, salt = b64decode(UID), N = 1_024, r = 4, p = 1, dkLen = 32, prf = prf)
        masterHash = SCRYPT(password = masterKey, salt = masterPassword, N = 1, r = 4, p = 1, dkLen = 64, prf = prf)
        authKey = b64encode_(SCRYPT(password = masterHash, salt = b64decode(salts[UID]), N = 1_024, r = 4, p = 1, dkLen = 128, prf = prf))

        if authKey not in dataBase:
            error('User Identification or Password is Incorrect.')

        del salts[UID]
        del dataBase[authKey]

        print('\nAction Confirmed.')
        dump(salts, open('salts.json', 'w'))
        dump(dataBase, open('dataBase.json', 'w'))
        exit()

    # Log Out
    elif action in {'log out', '4'}:
        dump(salts, open('salts.json', 'w'))
        dump(dataBase, open('dataBase.json', 'w'))
        exit()

    else:
        error('Action Unavailable')