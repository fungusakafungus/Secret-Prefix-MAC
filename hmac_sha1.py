import hashlib

__all__ = ['hmac_sha1',]

def xor(x, y):
    assert len(x) == len(y)
    return ''.join(chr(ord(a) ^ ord(b)) for (a,b) in zip(x, y))

def hmac_sha1(key, message):
    """
    >>> key = '\x0b' * 20
    >>> data = "Hi There"
    >>> from codecs import encode
    >>> encode(hmac_sha1(key, data), 'hex')
    'b617318655057264e28bc0b6fb378c8ef146be00'
    >>> alice_mac = hmac_sha1('secret','some text')
    >>> oscar_message = 'some text'.ljust(64) + 'Oscars text'
    >>> oscar_mac = hashlib.sha1(alice_mac + 'Oscars text')
    >>> oscar_mac == hmac_sha1('secret', oscar_message)
    False
    """
    
    B = 64
    ipad = '\x36' * B # the byte 0x36 repeated B times
    opad = '\x5C' * B # the byte 0x5C repeated B times

    # (1) append zeros to the end of K to create a B byte string
    #     (e.g., if K is of length 20 bytes and B=64, then K will be
    #     appended with 44 zero bytes 0x00)
    step1 = key.ljust(B, '\0')

    # (2) XOR (bitwise exclusive-OR) the B byte string computed in step
    #     (1) with ipad
    step2 = xor(step1, ipad)
    
    # (3) append the stream of data 'text' to the B byte string resulting
    #     from step (2)
    step3 = step2 + message
    
    # (4) apply H to the stream generated in step (3)
    sha1 = hashlib.sha1(step3)
    step4 = sha1.digest()

    # (5) XOR (bitwise exclusive-OR) the B byte string computed in
    #     step (1) with opad
    step5 = xor(step1, opad)
    
    # (6) append the H result from step (4) to the B byte string
    #     resulting from step (5)
    step6 = step5 + step4

    # (7) apply H to the stream generated in step (6) and output
    #     the result
    sha1 = hashlib.sha1(step6)
    return sha1.digest()

def usage():
    print """
Usage: 
    Create MAC for file:
        python hmac_sha1.py <key> <file>

    Verify MAC of a file:
        python hmac_sha1.py -v <key> <mac> <file>

    """
def main():
    import sys
    import codecs

    if len(sys.argv) < 3:
        usage()
        sys.exit()

    if sys.argv[1] == '-v': # -v for verify

        key, mac, message = sys.argv[2], codecs.decode(sys.argv[3], 'hex'), open(sys.argv[4]).read()
        if mac != hmac_sha1(key, message):
            print 'oh no, file corrupted!'
        else:
            print 'verified OK.'
    else:
        import codecs
        print codecs.encode(hmac_sha1(sys.argv[1], open(sys.argv[2]).read()), 'hex')

if __name__ == '__main__':
    main()
