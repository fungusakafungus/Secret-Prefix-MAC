def aes_cbc_mac(key, message):
    r"""
    Return MAC based on AES in CBC mode using 'key'

    Parameters:
        - key -- AES key must be either 16, 24, or 32 bytes long
        - message -- message to be processed

    Example:

    >>> alice_mac = aes_cbc_mac('secret','some text')
    >>> oscar_message = 'some text'.ljust(16, '\0') + 'Oscars text'
    >>> oscar_mac = aes_cbc_mac('', alice_mac + 'Oscars text')
    >>> oscar_mac == aes_cbc_mac('secret', oscar_message)
    False
    """
    import math
    import Crypto.Cipher.AES

    key = key.ljust(16, '#')[:16]
    aes = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC)
    message = message.ljust(int(math.ceil(len(message)/16.0)*16))

    res = aes.encrypt(message)

    return res[-32:]

def usage():
    print """
Usage: 
    Create MAC for file:
        python aes_cbc_mac.py <key> <file>

    Verify MAC of a file:
        python aes_cbc_mac.py -v <key> <mac> <file>

    """
def main():
    import sys
    import codecs

    if len(sys.argv) < 3:
        usage()
        sys.exit()

    if sys.argv[1] == '-v': # -v for verify

        key, mac, message = sys.argv[2], codecs.decode(sys.argv[3], 'hex'), open(sys.argv[4]).read()
        if mac != aes_cbc_mac(key, message):
            print 'oh no, file corrupted!'
        else:
            print 'verified OK.'
    else:
        import codecs
        print codecs.encode(aes_cbc_mac(sys.argv[1], open(sys.argv[2]).read()), 'hex')

if __name__ == '__main__':
    main()

