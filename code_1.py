# YOUR IMPORTS
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms,modes

# TASK 1
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
    
    return result # The result of XORing the string with the repeating key 

# TASK 2
def DHandEncrypt(A_Private_Key, B_Private_Key, PlainText):
    
    # making my argument keys into an actual pem format
    a_private_key = load_pem_private_key(A_Private_Key, password=None)
    b_private_key = load_pem_private_key(B_Private_Key, password=None)

    # now that they are an actual format we can get the public key from them directly
    a_public_key = a_private_key.public_key()
    b_public_key = b_private_key.public_key()

    # we exchange public keys so they can communicate and understand each other
    a_shared_key = a_private_key.exchange(b_public_key)
    b_shared_key = b_private_key.exchange(a_public_key)

    # check since they have to be the same
    if a_shared_key != b_shared_key:
        raise Exception("Shared keys are not equal")

    a_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(a_shared_key)

    # XOR Mechanism
    cipherText = bytes([b1 ^ b2 for b1,b2 in zip(PlainText, a_derived_key)])

    return a_derived_key, cipherText# You should return 2 variables, i.e., the derived key from Diffie-Hellman and ciphertext in this order.

# TASK 3
#https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/
#https://medium.com/asecuritysite-when-bob-met-alice/surely-no-one-uses-ecb-mode-in-aes-332ed90f29d0
def AES_CTR_Encrypt(key, nonce_counter, data):

    key = bytes.fromhex(key)
    nonce_counter = bytes.fromhex(nonce_counter)

    # get the block size of ECB encryption - splits data into multiple blocks of this size
    blockSize = algorithms.AES.block_size // 8
    nonceBlock = nonce_counter.ljust(blockSize, b'\x00')
    print(blockSize)

    #changing the model to ECB here
    aesCipher = Cipher(algorithms.AES(key), modes.ECB())
    aesEncryptor = aesCipher.encryptor()

    blockCounter = 0
    result = b''

    #floor division to find how many times you have to loop through
    for i in range(0, len(data), blockSize):
    
        #separation of data
        dataBlock = data[i:i + 16]

        #loop through it the number of times
        #for each convert it to int and then back to bytes and then add to nonce counter
        cipherText = aesEncryptor.update(nonceBlock)
        nonceBlock = int.to_bytes(int.from_bytes(nonceBlock, 'big') + blockCounter, blockSize, 'big')
        result += bytes(b ^ c for b,c in zip(dataBlock, cipherText))

        blockCounter += 1

    return result


if __name__ == "__main__":

    # TASK 1 
    result = RepeatingXOREncrypt("01", "0123")
    print(result)

    """
    Test case
    Input:
    key = "01" (this is a string)		
    string = "0123" (this is a string)
    Output: 00000202 (this is a hex value returned as a string)
    """

    # TASK 2
    A_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBm\nZK4qUqvU6WaPy4fNG9oWIXchxzztxmA7p9BFXbMzn3rHcW84SDwTWXAjkRd35XPV\n/9RAl06sv191BNFFPyg0\n-----END PRIVATE KEY-----\n'

    B_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBn\n9zn/q8GMs7SJjZ+VLlPG89bB83Cn1kDRmGEdUQF3OSZWIdMAVJb1/xaR4NAhlRya\n7jZHBW5DlUF5rrmecN4A\n-----END PRIVATE KEY-----\n'

    PlainText = b"Encrypt me with the derived key!"
	
    STD_KEY, STD_CIPHER = DHandEncrypt(A_PRIVATE_KEY, B_PRIVATE_KEY, PlainText)
    print(STD_KEY)
    print(STD_CIPHER)

    """
    Information on the type of variables:
    * A_Private_Key and B_Private_Key are in PEM format
    * Plaintext as bytes, e.g., b"this is a message"
    * Both the returned shared key and cipher have to be in bytes 

    Test case:
    Using the above private keys and PlainText = b"Encrypt me with the derived key!" the output should be the following:

    Output:
    You have to find the key by implementing DH, hence it can't be provide since it is part of the task's solution.
    XORing the key you have found with PlainText = b"Encrypt me with the derived key!" will result in:
    b'\xd8W\xd1\xfe\xb2\xb9_\x89\x90?O\tF\xde\xeb\xe1\xa1Gx\xb18\x1cY\x1e\xaf\xe0QmL\xf6\xeb\x0e'
    """

    # TASK 3
    key ='0000000000000000000000000000000000000000000000000000000000000001'
    nonce_counter = '00000000000000000000000000000001'
    data = b"12345678901234567890123456789012"
    result = AES_CTR_Encrypt(key, nonce_counter, data)
    print(result)