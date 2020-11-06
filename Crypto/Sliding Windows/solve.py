import requests
import base64
import binascii
import math
import string
import sys
import time
import re



#flag alphabet
flag_alphabet = string.digits + string.ascii_uppercase + string.ascii_lowercase + '{}_'

url = "http://localhost:8080/app/resetlink"
data = {"email":"a"}

#for debugging/better understanding of the script
verbose = False
if(len(sys.argv)==2 and sys.argv[1]=='v'):
    verbose = 1
if(len(sys.argv)==2 and sys.argv[1]=='vv'):
    verbose = 2
if(len(sys.argv)==2 and sys.argv[1]=='vvv'):
    verbose = 3

request_counter = 0
def getResetToken(msg):
    global request_counter
    request_counter+=1
    '''Get password reset token for the given string'''
    data["email"]=msg
    r = requests.post(url,data=data)
    #time.sleep(0.02)
    return base64.b64decode(r.text)

def details(token):
    '''
    Token length, number of blocks, and token itself
    Returns number of AES blocks in token
    '''
    print(f"len: {len(token)}", end=', ')
    print(f"blocks: {math.ceil(len(token)/16)}")
    if verbose: print(f"token:\n{token}")
    return len(token)//16+1

def blockify(st):
    'Split a string per 16 characters, return a list'
    return [st[i:i+16] for i in range(0, len(st), 16)]

def blockifyPrint(blocks,delim, binasci=False, end='\n'):
    '''Print blockify result, delimiting each block with delim parameter
    convert to hex representation if binasci=True
    '''
    for bl in blocks:
        if(binasci):
            print(binascii.hexlify(bl), end=delim)
        else:
            print(bl, end=delim)
            
    print('', end=end)



#terminal color codes
red="\033[1;31;40m"
green = "\033[1;32;40m"
gray = "\033[1;30;40m"
normal = "\033[0;37;40m"

#blockify print, but padding is red, flag is green, and unknown is gray
def blockifyColored(blocks):
    bucket = ''
    for bl in blocks:
        bucket = bucket + bl + " "

    bucket = re.sub('((A| ){2,128} ?)', (red + r"\1" + green), bucket)
    bucket = re.sub('((\?| ){2,128})', (gray + r"\1" + normal), bucket)
    print(bucket + " ", end='\r')



flaglen = 0
lastBlockCount=0
#Need to send 15 requests at most to calculate the flag length
for i in range(15):

    #send only pad
    token = getResetToken('A'*i)
    print(f"i: {i}", end=', ')
    newBlockCount = details(token)
    
    #if block count changed for this pad, we've hit (pad+flag)%16==1
    if(lastBlockCount and lastBlockCount!=newBlockCount):
        print(f"Block size change at {i} from {lastBlockCount} to {newBlockCount}")
        flaglen = (lastBlockCount-1)*16-i
        print(f"Flag length is {flaglen}.")
        break
    lastBlockCount=newBlockCount

#minimum number of blocks we need to pad to left to get complete flag
slideBlockCount=math.ceil(flaglen/16)

#iterator for the left-pad
slideLength=slideBlockCount*16 -1 
print(f"Need {slideBlockCount} blocks and {slideLength} characters to have space for sliding.")
print("Starting right to left sliding window attack.")



flag = ''

#remove a character from left pad each iteration, brute forcing the flag one character at a time
#stop when flaglen is exhausted
for i in range(flaglen):

    #get token for the base request of this iteration, last character is unknown.
    #we will need to match this ciphertext when brute forcing
    leftpad = 'A'*(slideLength-i)
    token = getResetToken(leftpad)
    
    #currentSignificantBlockIndex is the index of first block that will matter.
    #Blocks where no change has happened will always match
    blocks = blockify(token)
    currentSignificantBlockIndex = ((slideLength-1)//16)

    #debugging - show blocks
    if verbose>=2: 
        print("\n\n\n\n")
        print("New block map")
        blockifyPrint(blocks,'\n', 1)

    #will only compare block at SBI
    significantBlock = blocks[currentSignificantBlockIndex]

    #print the state, show left pad + found flag + unknown in block format
    pld = leftpad+flag+(flaglen-i)*'?'
    #blockifyPrint(blockify(pld),' ', '')
    if verbose>=2: 
        print(f"Significant block is: {binascii.hexlify(significantBlock)}")
        print(f"Brute forcing last character to get letter")
        print("\n")

    

    #brute force last character of significant block from flag_alphabet
    for symbol in flag_alphabet:
        #brute force payload
        brutepld = 'A'*(slideLength-i) + flag + symbol

        #print current payload in blockified format
        if verbose>=2: blockifyColored(blockify(brutepld + '?'*(flaglen-i)))
        
        #get reset token and split it in blocks
        brutetoken = getResetToken(brutepld)
        bruteblocks = blockify(brutetoken)
        if verbose>=3: print(f"\nCipher Blocks: (looking for {currentSignificantBlockIndex+1}:{binascii.hexlify(significantBlock)})")
        if verbose>=3: blockifyPrint(bruteblocks,'\n', 1)
       
        #block to compare
        currentSignificantBlock=bruteblocks[currentSignificantBlockIndex]

        if verbose>=3: print(f"{symbol}:{binascii.hexlify(currentSignificantBlock)}")

        #found unknown character
        if(currentSignificantBlock==significantBlock):
            if verbose>=2: print(f"Match found: {symbol}{' '*(slideLength+flaglen)}")
            if verbose==1:
                blockifyColored(blockify(brutepld + (flaglen-i)*'?'))
                print()
            else:
                blockifyColored(blockify(brutepld + (flaglen-i)*'?'))
            #blockifyPrint(blockify(brutepld), ' ', 0, '\r\r')
            flag+=symbol
            break

print("\033[0;37;40m                                                                       ")
print(f"Total requests: {request_counter}")
print(f"flag: {green}{flag}{normal}")
