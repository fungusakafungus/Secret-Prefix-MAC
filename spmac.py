from merkledamgard import merkledamgard

def main():
    """Compute a MAC from key and message.

    Usage:
        python spmac.py key filename
    """
    import codecs
    import sys
    import getopt
    hex_options = ('hexout','hexkey','hexin')
    options, args = getopt.getopt(sys.argv[1:], 'hH', hex_options)
    options = dict((option[0].lstrip('-'), 1) for option in options)

    # if -h is in options, remove it and set hexin and hexkey
    if 'h' in options:
        options['hexin'] = options['hexkey'] = 1

    # if -H is in options, remove it and set hexin, hexout and hexkey
    if 'H' in options:
        options['hexin'] = options['hexkey'] = options['hexout'] = 1

    key, filename = args

    if 'hexkey' in options:
        key = codecs.decode(key, 'hex')

    if 'hexin' in options:
        cleartext = codecs.open(filename, 'r', 'hex').read()
    else:
        cleartext = open(filename, 'r').read()

    output = spmac(key, cleartext)

    #import ipdb; ipdb.set_trace()
    if 'hexout' in options:
        output = codecs.encode(output, 'hex')

    print output

_block_size = 8

def _compression_func_xor(block1, block2):
    return ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(block1, block2)])

_padding_func_zero = lambda partial_block, _block_size:\
    partial_block.ljust(_block_size,'\0')

_iv = '\0' * _block_size

xor_hash = merkledamgard(_compression_func_xor, _padding_func_zero, _block_size,
        _iv)

def spmac(key, cleartext):
    r"""Return secret prefix message authentication code for 'cleartext' using key 'key'.

    Secret prefix mac based on Merkle-Damgard construction-based hashing algorithm is insecure:
    >>> mac = spmac('abc', 'the message')
    >>> mac
    '\x04\x11\x10\x15\x0f\x00 m'
    >>> oscars_message = 'the message\0\0Owned!'
    >>> oscars_mac = spmac('', mac + 'Owned!\0\0')
    >>> oscars_mac
    'Kf~pk! m'
    >>> oscars_mac == spmac('abc', oscars_message)
    True
    """
    return xor_hash(key + cleartext)

if __name__ == '__main__':
    main()
