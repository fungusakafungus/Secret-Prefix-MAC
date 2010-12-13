from merkledamgard import merkledamgard

def main(argv):
    """Compute a MAC from key and message.

    Usage:
        python spmac.py key filename
    """
    key, filename = argv[1:]

    print spmac(key, open(filename, 'r').read())


_block_size = 8

def _compression_func_xor(block1, block2):
    return ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(block1, block2)])

_padding_func_zero = lambda partial_block: partial_block.ljust(_block_size,'\0')

_iv = '\0' * _block_size

_hash = merkledamgard(_compression_func_xor, _padding_func_zero,
    _block_size, _iv)

def spmac(key, cleartext):
    return _hash(key + cleartext)

if __name__ == '__main__':
    import sys
    main(sys.argv)
