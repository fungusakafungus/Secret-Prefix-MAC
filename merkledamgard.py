def merkledamgard(compression_func, padding_func, block_size, iv):
    r"""Return a hash function hash(cleartext) based on parameters.

    Parameters:
      - compression_func(block1, block2) -> block -- one-way cryptographic
            compression function, parameters and return value are 'block_size'
            bytes long

      - padding_func(partial_block, block_size) -> block -- padding function, should return
            'partial_block' padded to be 'block_size' bytes long. For example,
            lambda partial_block: p.ljust(block_size, '\0')

      - block_size -- integer, block size of Merkle-Damgard Construction

      - iv -- initialization vector, string of 'block_size' bytes

    Padding is performed also if cleartext length is a multiple of
    'block_size'.

    Examples:

    Let block_size be two bytes:
    >>> block_size=2

    Compression function just xors its arguments bytewise
    >>> def compression_func_xor(block1, block2):
    ...     return ''.join([chr(ord(x) ^ ord(y)) for x, y in zip(block1, block2)])

    Padding with null bytes:
    >>> padding_func_zero = lambda partial_block, block_size: partial_block.ljust(block_size,'\0')
    >>> padding_func_zero('a', 2)
    'a\x00'

    Padding is performed on empty input:
    >>> padding_func_zero('', 2)
    '\x00\x00'

    Let the IV be all zeros:
    >>> iv = '\0\0'

    Create the hash function:
    >>> hash = merkledamgard(compression_func_xor, padding_func_zero,
    ... block_size, iv)

    And now, use the hash function:
    >>> hash('')
    '\x00\x00'
    >>> hash('\0\1\2\3')
    '\x02\x02'
    >>> hash('abc')
    '\x02b'

    Cleartext which length is multiple of block_size should be extended with a
    whole new block of padding:
    >>> padding_func_one = lambda partial_block, block_size: partial_block.ljust(block_size,'\1')
    >>> hash1 = merkledamgard(compression_func_xor, padding_func_one,
    ... block_size, iv)
    >>> hash1('\0\0')
    '\x01\x01'

    Hash length is block size.
    >>> hash2 = merkledamgard(compression_func_xor, padding_func_one,
    ... 2, '\0'*2)
    >>> hash3 = merkledamgard(compression_func_xor, padding_func_one,
    ... 3, '\0'*3)
    >>> hash10 = merkledamgard(compression_func_xor, padding_func_one,
    ... 10, '\0'*10)
    >>> len(hash2('abc'))
    2
    >>> len(hash3('abc'))
    3
    >>> len(hash10('abc'))
    10

    Length of iv should be block_size, it is checked:
    >>> hash10 = merkledamgard(compression_func_xor, padding_func_one,
    ... 10, '\0'*100)
    Traceback (most recent call last):
    ...
    ValueError: iv length not equal to block_size

    """

    if len(iv) != block_size:
        raise ValueError("iv length not equal to block_size")

    def hash(cleartext):
        result = iv
        for i in xrange(0, len(cleartext) + 1, block_size):
            # include upper bound;
            # if cleartext is '1234' and block_size is 2, i goes 0, 2, 4
            block = cleartext[i:i + block_size]
            if not len(block) == block_size:
                block = padding_func(block, block_size)
            result = compression_func(result, block)
        return result

    return hash
