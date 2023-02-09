# YOUR IMPORTS
import string
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def RepeatingXOREncrypt(key, string):
	# YOUR IMPEMENTATION
    # converting the string into bytes
    keyB = bytes(key, 'utf-8')
    stringB = bytes(string, 'utf-8')

    # calculating the length of the string
    pt = stringB
    lengthStr = len(stringB)
    lengthKey = len(keyB)

    encoded = []

    #perform XOR with key in args with every character in string
    for i in range(lengthStr):
        encoded.append(pt[i] ^ keyB[i % lengthKey])

    # converting the bytes into a hex
    result = bytes(encoded).hex()
    
    return result
    # The result of XORing the string with the repeating key 

def DHandEncrypt(A_Private_Key, B_Private_Key, PlainText):
#TODO

    return # You should return 2 variables, i.e., the derived key from 
    #Diffie-Hellman and ciphertext in this order.



if __name__ == "__main__":

    # TASK 1 
    result = RepeatingXOREncrypt("01", "0123")
    print(result)

#Test case
#Input:
#key = "01" (this is a string)		
#string = "0123" (this is a string)
#Output: 00000202 (this is a hex value returned as a string)

    # TASK 2
    A_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBm\nZK4qUqvU6WaPy4fNG9oWIXchxzztxmA7p9BFXbMzn3rHcW84SDwTWXAjkRd35XPV\n/9RAl06sv191BNFFPyg0\n-----END PRIVATE KEY-----\n'

    B_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBn\n9zn/q8GMs7SJjZ+VLlPG89bB83Cn1kDRmGEdUQF3OSZWIdMAVJb1/xaR4NAhlRya\n7jZHBW5DlUF5rrmecN4A\n-----END PRIVATE KEY-----\n'

    PlainText = b"Encrypt me with the derived key!"
	
    STD_KEY, STD_CIPHER = DHandEncrypt(A_PRIVATE_KEY, B_PRIVATE_KEY, PlainText)

#Information on the type of variables:
#* A_Private_Key and B_Private_Key are in PEM format
#* Plaintext as bytes, e.g., b"this is a message"
#* Both the returned shared key and cipher have to be in bytes 

#Test case:
#Using the above private keys and PlainText = b"Encrypt me with the derived key!" the output should be the following:

#Output:
#You have to find the key by implementing DH, hence it can't be provide since it is part of the task's solution.
#XORing the key you have found with PlainText = b"Encrypt me with the derived key!" will result in:
#b'\xd8W\xd1\xfe\xb2\xb9_\x89\x90?O\tF\xde\xeb\xe1\xa1Gx\xb18\x1cY\x1e\xaf\xe0QmL\xf6\xeb\x0e'