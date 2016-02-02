#! /usr/bin/env python
# -*- coding: utf8 -*-


import sys, datetime
import string, random, hashlib

# MD5 unix passwd generator, inspired from
# http://www.vidarholen.net/contents/blog/?p=32

def generateSalt():
    size = 8
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(size))
    

def generateShadowLine(user, passwd, salt=''):
    if salt:
        password = generatePassword(passwd, salt)
    else:
        password = generatePassword(passwd, generateSalt())

#     - Username, up to 8 characters. Case-sensitive, usually all lowercase. A direct match to the username in the /etc/passwd file.
#     - Password, 13 character encrypted. A blank entry (eg. ::) indicates a password is not required to log in (usually a bad idea), and a ``*'' entry (eg. :*:) indicates the account has been disabled.
#     - The number of days (since January 1, 1970) since the password was last changed.
#     - The number of days before password may be changed (0 indicates it may be changed at any time)
#     - The number of days after which password must be changed (99999 indicates user can keep his or her password unchanged for many, many years)
#     - The number of days to warn user of an expiring password (7 for a full week)
#     - The number of days after password expires that account is disabled
#     - The number of days since January 1, 1970 that an account has been disabled
#     - A reserved field for possible future use

    epoch = datetime.date(1970, 1, 1)
    today = datetime.date.today()
    delta = (today - epoch).days

    line = '%s:%s:%d:0:99999:7:::' % (user, password, delta)

    return line


def generatePassword(passwd, salt):
    magic = '$1$'

    # Initialization

    # Start by computing the Alternate sum, md5(password + salt + password)
    alternate = hashlib.md5(passwd + salt + passwd).digest()
    # print alternate
    # Compute the Intermediate0 sum by hashing the concatenation of the following strings:
    # - Password
    # - Magic
    # - Salt
    intermediate = passwd + magic + salt

    # - length(password) bytes of the Alternate sum, repeated as necessary
    for i in range(len(passwd)):
        intermediate += alternate[i%len(alternate)]
        
    # - For each bit in length(password), from low to high and stopping after the most significant set bit
    # If the bit is set, append a NUL byte
    # If it's unset, append the first byte of the password
    lp = len(passwd)
    while lp != 0:
        if (lp & 1) == 1:
            intermediate += '\x00'
        else:
            intermediate += passwd[0]
        lp >>=1
       
    intermediate = hashlib.md5(intermediate).digest()
    # Loop

    # For i = 0 to 999 (inclusive), compute Intermediatei+1 by concatenating and hashing the following:
    for i in range(1000):
        # - If i is even, Intermediatei
        # - If i is odd, password
        if i & 1:
            acc = passwd
        else:
            acc = intermediate
        
        # - If i is not divisible by 3, salt
        if i % 3:
            acc += salt
        # - If i is not divisible by 7, password
        if i % 7:
            acc += passwd
        # - If i is even, password
        # - If i is odd, Intermediatei
        if i & 1:
            acc += intermediate
        else:
            acc += passwd
        
        intermediate = hashlib.md5(acc).digest()
        
    # finalization
    # Output the magic
    # Output the salt
    # Output a "$" to separate the salt from the encrypted section
    final = magic + salt + '$'
    b64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        
    # Pick out the 16 bytes in this order: 11 4 10 5 3 9 15 2 8 14 1 7 13 0 6 12
    intermediate = ''.join(intermediate[i] for i in [11, 4, 10, 5, 3, 9, 15, 2, 8, 14, 1, 7, 13, 0, 6, 12])


    # For each group of 6 bits (there are 22 groups), starting with the least significant
    # Output the corresponding base64 character with this index
    bitsArray = []
    for i in range(15, -1, -1):
        val = intermediate[i]
        for j in range(8):
            bitsArray.append((ord(val) >> j) & 1)

    groups = []
    while len(bitsArray):
        groups.append(bitsArray[0:6])
        bitsArray = bitsArray[6:]

    intGroups = []
    for group in groups:
        val = 0
        for i in range(len(group)):
            val += group[i] * pow(2, i)
        intGroups.append(val)

    for i in intGroups:
        final += b64[i]
            
    return final
    

def usage():
    print '''
    generateShadow.py USER PASSWORD [SALT]

    Generate the /etc/shadow's format line corresponding to the given user and password.
    It uses an MD5 ($1$) based encryption format.

    - USER : A user name, as in /etc/passwd
    - PASSWORD : The choosen password for this username
    - [SALT] is optional. If missing, a random one will be generated
'''


if __name__ == '__main__':
    if len(sys.argv) < 3:
        usage()
    elif len(sys.argv) == 3:
        print generateShadowLine(sys.argv[1], sys.argv[2]) 
    elif len(sys.argv) == 4:
        print generateShadowLine(sys.argv[1], sys.argv[2], sys.argv[3]) 

# redhat123 -> $ 1 $ jp5rCMS4 $ mhvf4utonDubW5M00z0Ow0
